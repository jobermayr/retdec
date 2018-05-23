/**
* @file src/bin2llvmir/optimizations/unreachable_funcs/unreachable_funcs.cpp
* @brief Implementation of UnreachableFuncs optimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iostream>
#include <string>

#include <llvm/IR/Constants.h>

#include "retdec/utils/container.h"
#include "retdec/bin2llvmir/analyses/reachable_funcs_analysis.h"
#include "retdec/bin2llvmir/optimizations/unreachable_funcs/unreachable_funcs.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/**
* @brief Removes function from current module.
*
* @param[in] funcToRemove Function to remove.
* @param[in] callGraph Call graph of module.
*/
void removeFuncFromModule(Function& funcToRemove, CallGraph& callGraph)
{
	CallGraphNode* funcToRemoveNode(callGraph[&funcToRemove]);
	for (auto& item : callGraph)
	{
		item.second->removeAnyCallEdgeTo(funcToRemoveNode);
	}
	funcToRemove.replaceAllUsesWith(UndefValue::get(funcToRemove.getType()));
	funcToRemoveNode->removeAllCalledFunctions();
	funcToRemove.deleteBody();

	callGraph.removeFunctionFromModule(funcToRemoveNode);
}

bool userCannotBeOptimized(User* user, const std::set<llvm::Function*>& funcs)
{
	if (auto* inst = dyn_cast<Instruction>(user))
	{
		auto* pf = inst->getFunction();
		if (pf == nullptr || hasItem(funcs, pf))
		{
			return true;
		}
	}
	else if (auto* ce = dyn_cast<ConstantExpr>(user))
	{
		for (auto* u : ce->users())
		{
			if (userCannotBeOptimized(u, funcs))
			{
				return true;
			}
		}
	}
	else
	{
		return true;
	}

	return false;
}

/**
* @brief Returns @c true if @a func can't be optimized, otherwise @c false.
*
* For more details what can't be optimized @see getFuncsThatCannotBeOptimized().
*/
bool cannotBeOptimized(Function& func, const std::set<llvm::Function*>& funcs)
{
	for (auto* u : func.users())
	{
		if (userCannotBeOptimized(u, funcs))
		{
			return true;
		}
	}

	return false;
}

} // anonymous namespace

// It is the address of the variable that matters, not the value, so we can
// initialize the ID to anything.
char UnreachableFuncs::ID = 0;

RegisterPass<UnreachableFuncs> UnreachableFuncsRegistered(
		"unreachable-funcs",
		"Unreachable functions optimization",
		false,
		false);

/**
* @brief Created a new unreachable functions optimizer.
*/
UnreachableFuncs::UnreachableFuncs() :
		ModulePass(ID),
		mainFunc(nullptr)
{

}

void UnreachableFuncs::getAnalysisUsage(AnalysisUsage& au) const
{
	au.addRequired<CallGraphWrapperPass>();
}

bool UnreachableFuncs::runOnModule(Module& m)
{
	module = &m;
	config = ConfigProvider::getConfig(module);
	return run();
}

bool UnreachableFuncs::runOnModuleCustom(llvm::Module& m, Config* c)
{
	module = &m;
	config = c;
	return run();
}

bool UnreachableFuncs::run()
{
	if (config == nullptr)
	{
		return false;
	}
	if (config->getConfig().fileType.isShared()
			|| config->getConfig().fileType.isObject())
	{
		return false;
	}

	// The main function has to be a definition, not just a declaration. This
	// is needed when decompiling shared libraries containing an import of main.
	//
	mainFunc = config->getLlvmFunction(config->getConfig().getMainAddress());
	if (mainFunc == nullptr || mainFunc->isDeclaration())
	{
		return false;
	}

	CallGraph& callGraph(getAnalysis<CallGraphWrapperPass>().getCallGraph());

	std::set<llvm::Function*> funcsThatCannotBeOptimized;

	addToSet(
			ReachableFuncsAnalysis::getReachableDefinedFuncsFor(
					*mainFunc,
					*module,
					callGraph),
			funcsThatCannotBeOptimized);
	addToSet(
			ReachableFuncsAnalysis::getGloballyReachableFuncsFor(*module),
			funcsThatCannotBeOptimized);
	addToSet(
			getFuncsThatCannotBeOptimized(funcsThatCannotBeOptimized),
			funcsThatCannotBeOptimized);

	removeFuncsThatCanBeOptimized(funcsThatCannotBeOptimized);

	return NumFuncsRemoved > 0;
}

/**
* @brief Returns functions that can't be optimized.
*
* - We don't want optimize functions, that has use in reachable functions. It is
*   needed because address of these functions can be taken and then used.
* - We don't want optimize functions which address is taken and stored into
*   global variables.
* - We don't want to optimize functions, which are used in statistics.
*
* @param[in] reachableFuncs Reachable functions.
* @param[in] module Current module.
*/
std::set<llvm::Function*> UnreachableFuncs::getFuncsThatCannotBeOptimized(
		const std::set<llvm::Function*>& reachableFuncs) const
{
	std::set<llvm::Function*> result;
	for (Function& func : *module)
	{
		if (cannotBeOptimized(func, reachableFuncs))
		{
			result.insert(&func);
		}
	}

	return result;
}

/**
* @brief Returns functions that can be optimized in a module.
*
* @param[in] funcsThatCannotBeOptimized Functions that can't be optimized.
* @param[in] module We want optimize functions in this module.
*
* @return Functions to optimize.
*/
std::set<llvm::Function*> UnreachableFuncs::getFuncsThatCanBeOptimized(
		const std::set<llvm::Function*>& funcsThatCannotBeOptimized) const
{
	std::set<llvm::Function*> toBeOptimized;
	for (Function& func : *module)
	{
		if (func.isDeclaration())
		{
			// We don't want to optimize functions only with declaration.
			continue;
		}

		if (hasItem(funcsThatCannotBeOptimized, &func))
		{
			continue;
		}

		if (&func == mainFunc)
		{
			// We don't want to remove main function.
			continue;
		}

		toBeOptimized.insert(&func);
	}

	return toBeOptimized;
}

/**
* @brief Removes unreachable functions from main.
*
* @param[in] funcsThatCannotBeOptimized Functions that can't be optimized.
* @param[in] module Module with functions.
*/
void UnreachableFuncs::removeFuncsThatCanBeOptimized(
		const std::set<llvm::Function*>& funcsThatCannotBeOptimized)
{
	std::set<llvm::Function*> toRemove(
			getFuncsThatCanBeOptimized(funcsThatCannotBeOptimized));
	removeFuncsFromModule(toRemove);
}

/**
* @brief Removes functions from current module.
*
* @param[in] funcsToRemove Functions to remove.
*/
void UnreachableFuncs::removeFuncsFromModule(
		const std::set<llvm::Function*>& funcsToRemove)
{
	CallGraph& callGraph(getAnalysis<CallGraphWrapperPass>().getCallGraph());
	for (Function* func : funcsToRemove)
	{
		removeFuncFromModule(*func, callGraph);
		NumFuncsRemoved++;
	}
}

} // namespace bin2llvmir
} // namespace retdec
