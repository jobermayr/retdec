/**
* @file src/bin2llvmir/optimizations/stack_protect/stack_protect.cpp
* @brief Protect stack variables from LLVM optimization passes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <iomanip>
#include <iostream>
#include <stack>

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/stack_protect/stack_protect.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/bin2llvmir/utils/utils.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char StackProtect::ID = 0;

std::map<llvm::Type*, llvm::Function*> StackProtect::_type2fnc;

static RegisterPass<StackProtect> X(
		"stack-protect",
		"Stack protection optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

StackProtect::StackProtect() :
		ModulePass(ID)
{

}

bool StackProtect::runOnModule(Module& M)
{
	_module = &M;
	_config = ConfigProvider::getConfig(&M);
	return run();
}

bool StackProtect::runOnModuleCustom(llvm::Module& M, Config* c)
{
	_module = &M;
	_config = c;
	return run();
}

/**
 * @return @c True if module @a _module was modified in any way,
 *         @c false otherwise.
 */
bool StackProtect::run()
{
	if (_config == nullptr)
	{
		return false;
	}

	_type2fnc.empty() ? protect() : unprotect();

	return true;
}

void StackProtect::protect()
{
	protectStack();

	if (_config->getConfig().isIda()
			&& _config->getConfig().parameters.isSomethingSelected())
	{
		protectRegisters();
	}
}

void StackProtect::protectStack()
{
	for (Function& F : _module->getFunctionList())
	for (Instruction& I : instructions(&F))
	{
		auto* a = dyn_cast<AllocaInst>(&I);
		if (!_config->isStackVariable(a))
		{
			continue;
		}

		protectValue(a, a->getAllocatedType(), a->getNextNode());
	}
}

void StackProtect::protectRegisters()
{
	for (Function& F : _module->getFunctionList())
	{
		auto it = inst_begin(&F);
		if (it == inst_end(&F)) // no instructions in function
		{
			continue;
		}
		Instruction* first = &*it;

		for (GlobalVariable& gv : _module->globals())
		{
			if (!_config->isRegister(&gv))
			{
				continue;
			}

			protectValue(&gv, gv.getValueType(), first);
		}
	}
}

void StackProtect::unprotect()
{
	for (auto& p : _type2fnc)
	{
		auto* fnc = p.second;

		for (auto uIt = fnc->user_begin(); uIt != fnc->user_end();)
		{
			auto* u = *uIt;
			++uIt;

			for (auto uuIt = u->user_begin(); uuIt != u->user_end();)
			{
				auto* uu = *uuIt;
				++uuIt;

				if (auto* s = dyn_cast<StoreInst>(uu))
				{
					s->eraseFromParent();
				}
			}

			Instruction* i = cast<Instruction>(u);
			i->replaceAllUsesWith(UndefValue::get(i->getType()));
			i->eraseFromParent();
		}

		fnc->eraseFromParent();
	}

	_type2fnc.clear();
}

void StackProtect::protectValue(
		llvm::Value* val,
		llvm::Type* t,
		llvm::Instruction* before)
{
	Function* fnc = getOrCreateFunction(t);
	auto* c = CallInst::Create(fnc);
	c->insertBefore(before);
	auto* s = new StoreInst(c, val);
	s->insertAfter(c);
}

llvm::Function* StackProtect::getOrCreateFunction(llvm::Type* t)
{
	auto fIt = _type2fnc.find(t);
	return fIt != _type2fnc.end() ? fIt->second : createFunction(t);
}

llvm::Function* StackProtect::createFunction(llvm::Type* t)
{
	FunctionType* ft = FunctionType::get(t, false);
	auto* fnc = Function::Create(
			ft,
			GlobalValue::ExternalLinkage,
			names::generateFunctionNameUndef(_type2fnc.size()),
			_module);
	_type2fnc[t] = fnc;

	return fnc;
}

} // namespace bin2llvmir
} // namespace retdec
