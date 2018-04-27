/**
* @file src/bin2llvmir/optimizations/value_protect/value_protect.cpp
* @brief Protect values from LLVM optimization passes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/bin2llvmir/optimizations/value_protect/value_protect.h"
#include "retdec/bin2llvmir/providers/names.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char ValueProtect::ID = 0;

std::map<llvm::Type*, llvm::Function*> ValueProtect::_type2fnc;

static RegisterPass<ValueProtect> X(
		"value-protect",
		"Value protection optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

ValueProtect::ValueProtect() :
		ModulePass(ID)
{

}

bool ValueProtect::runOnModule(Module& M)
{
	_module = &M;
	_config = ConfigProvider::getConfig(&M);
	return run();
}

bool ValueProtect::runOnModuleCustom(llvm::Module& M, Config* c)
{
	_module = &M;
	_config = c;
	return run();
}

/**
 * @return @c True if module @a _module was modified in any way,
 *         @c false otherwise.
 */
bool ValueProtect::run()
{
	if (_config == nullptr)
	{
		return false;
	}

	_type2fnc.empty() ? protect() : unprotect();

	return true;
}

void ValueProtect::protect()
{
	_config->getConfig().parameters.frontendFunctions.insert(
			names::generatedUndefFunctionPrefix);

	protectStack();

	if (_config->getConfig().isIda()
			&& _config->getConfig().parameters.isSomethingSelected())
	{
		protectRegisters();
	}
}

void ValueProtect::protectStack()
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

void ValueProtect::protectRegisters()
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

void ValueProtect::unprotect()
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
			if (i->user_empty())
			{
				i->eraseFromParent();
			}
		}

		if (fnc->user_empty())
		{
			fnc->eraseFromParent();
		}
	}

	_type2fnc.clear();
}

void ValueProtect::protectValue(
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

llvm::Function* ValueProtect::getOrCreateFunction(llvm::Type* t)
{
	auto fIt = _type2fnc.find(t);
	return fIt != _type2fnc.end() ? fIt->second : createFunction(t);
}

llvm::Function* ValueProtect::createFunction(llvm::Type* t)
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
