/**
* @file src/bin2llvmir/optimizations/inst_opt/inst_opt.cpp
* @brief Instruction optimizations which we want to do ourselves.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/instruction.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/utils.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char InstOpt::ID = 0;

static RegisterPass<InstOpt> X(
		"inst-opt",
		"Assembly instruction optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

InstOpt::InstOpt() :
		ModulePass(ID)
{

}

bool InstOpt::runOnModule(Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	removeInstructionNames();
	return run();
}

bool InstOpt::runOnModuleCustom(llvm::Module& m, Config* c)
{
	_module = &m;
	_config = c;
	return run();
}

bool InstOpt::run()
{
	bool changed = false;

	changed |= runGeneralOpts();

	return changed;
}

/**
 * TODO: Instruction names in LLVM IR slow down all the optimizations.
 * The new capstone2llvmir decoder does not generate names, so maybe we can
 * remove this code.
 */
void InstOpt::removeInstructionNames()
{
	for (auto& f : _module->getFunctionList())
	{
		auto it = inst_begin(f);
		auto e = inst_end(f);
		while (it != e)
		{
			Instruction* i = &(*it);
			++it;

			if (i->hasName())
			{
				i->setName(Twine());
			}
		}
	}
}

bool InstOpt::runGeneralOpts()
{
	bool changed = false;

	for (auto& F : _module->getFunctionList())
	{
		for (auto ai = AsmInstruction(&F); ai.isValid(); ai = ai.getNext())
		{
			std::set<Instruction*> toErase;

			for (auto& i : ai)
			{
				if (!isa<BinaryOperator>(i))
				{
					continue;
				}

				auto* op0 = dyn_cast<LoadInst>(i.getOperand(0));
				auto* op1 = dyn_cast<LoadInst>(i.getOperand(1));
				if (!(op0 && op1 && op0->getPointerOperand() == op1->getPointerOperand()))
				{
					continue;
				}
				AsmInstruction op0Asm(op0);
				AsmInstruction op1Asm(op1);
				if ((op0Asm != op1Asm) || (op0Asm != ai))
				{
					continue;
				}

				if (i.getOpcode() == Instruction::Xor)
				{
					i.replaceAllUsesWith(ConstantInt::get(i.getType(), 0));
					toErase.insert(&i);
					if (op0 != op1)
					{
						op1->replaceAllUsesWith(op0);
						toErase.insert(op1);
					}
					changed = true;
				}
				else if (i.getOpcode() == Instruction::Or
						|| i.getOpcode() == Instruction::And)
				{
					i.replaceAllUsesWith(op0);
					toErase.insert(&i);
					if (op0 != op1)
					{
						op1->replaceAllUsesWith(op0);
						toErase.insert(op1);
					}
					changed = true;
				}
			}

			for (auto* i : toErase)
			{
				i->eraseFromParent();
				changed = true;
			}
		}
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
