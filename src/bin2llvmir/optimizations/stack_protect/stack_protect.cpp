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

	bool changed = false;

	if (!_type2fnc.empty())
	{
		changed |= unprotectStack(nullptr);
	}
	else
	{
		changed |= protectStack();
	}

	return changed;
}

bool StackProtect::protectStack()
{
	for (auto& F : _module->getFunctionList())
	for (auto& B : F)
	for (Instruction& I : B)
	{
		auto* a = dyn_cast<AllocaInst>(&I);
		if (!_config->isStackVariable(a))
		{
			continue;
		}

		for (auto* u : a->users())
		{
			auto* s = dyn_cast<StoreInst>(u);
			if (s && s->getPointerOperand() == a && s->getParent() == a->getParent())
			{
				continue;
			}
		}

		Function* fnc = nullptr;

		auto* t = a->getAllocatedType();
		auto fIt = _type2fnc.find(t);
		if (fIt != _type2fnc.end())
		{
			fnc = fIt->second;
		}
		else
		{
			FunctionType* ft = FunctionType::get(
					t,
					false);
			fnc = Function::Create(
					ft,
					GlobalValue::ExternalLinkage,
					_fncName + std::to_string(_type2fnc.size()),
					_module);

			_type2fnc[t] = fnc;
		}

		auto* c = CallInst::Create(fnc);
		c->insertAfter(a);
		auto* conv = convertValueToTypeAfter(c, t, c);
		assert(isa<Instruction>(conv));
		auto* s = new StoreInst(conv, a);
		s->insertAfter(cast<Instruction>(conv));
	}

	if (_config->getConfig().isIda()
			&& _config->getConfig().parameters.isSomethingSelected())
	{
		for (Function& F : _module->getFunctionList())
		{
			if (F.isDeclaration())
			{
				continue;
			}

			for (auto& gv : _module->globals())
			{
				if (!_config->isRegister(&gv))
				{
					continue;
				}

				Function* fnc = nullptr;

				auto* t = gv.getValueType();
				auto fIt = _type2fnc.find(t);
				if (fIt != _type2fnc.end())
				{
					fnc = fIt->second;
				}
				else
				{
					FunctionType* ft = FunctionType::get(
							t,
							false);
					fnc = Function::Create(
							ft,
							GlobalValue::ExternalLinkage,
							_fncName + std::to_string(_type2fnc.size()),
							_module);

					_type2fnc[t] = fnc;
				}

				auto it = inst_begin(&F);
				assert(it != inst_end(&F));
				auto* firstI = &*it;

				auto* c = CallInst::Create(fnc);
				c->insertBefore(firstI);
				auto* conv = convertValueToTypeAfter(c, t, c);
				assert(isa<Instruction>(conv));
				auto* s = new StoreInst(conv, &gv);
				s->insertAfter(cast<Instruction>(conv));
			}
		}
	}

	return true;
}

bool StackProtect::unprotectStack(llvm::Function* f)
{
	for (auto& p : _type2fnc)
	{
		auto* fnc = p.second;

		for (auto uIt = fnc->user_begin(); uIt != fnc->user_end();)
		{
			auto* u = *uIt;
			++uIt;

			CallInst* c = dyn_cast<CallInst>(u);
			assert(c);

			for (auto uuIt = u->user_begin(); uuIt != u->user_end();)
			{
				auto* uu = *uuIt;
				++uuIt;

				if (auto* s = dyn_cast<StoreInst>(uu))
				{
					s->eraseFromParent();
				}
			}

			c->replaceAllUsesWith(UndefValue::get(c->getType()));
			c->eraseFromParent();
		}

		fnc->eraseFromParent();
	}

	return true;
}

} // namespace bin2llvmir
} // namespace retdec
