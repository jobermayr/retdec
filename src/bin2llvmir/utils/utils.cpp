/**
 * @file src/llvm-support/utils.cpp
 * @brief LLVM Utility functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Support/Casting.h>

namespace retdec {
namespace bin2llvmir {

/**
 * Skips both casts and getelementptr instructions and constant expressions.
 */
llvm::Value* skipCasts(llvm::Value* val)
{
	while (true)
	{
		if (auto* c = llvm::dyn_cast_or_null<llvm::CastInst>(val))
		{
			val = c->getOperand(0);
		}
		else if (auto* p = llvm::dyn_cast_or_null<llvm::GetElementPtrInst>(val))
		{
			val = p->getOperand(0);
		}
		else if (auto* ce = llvm::dyn_cast_or_null<llvm::ConstantExpr>(val))
		{
			if (ce->isCast()
					|| ce->getOpcode() == llvm::Instruction::GetElementPtr)
			{
				val = ce->getOperand(0);
			}
			else
			{
				return val;
			}
		}
		else
		{
			return val;
		}
	}

	return val;
}

} // namespace bin2llvmir
} // namespace retdec
