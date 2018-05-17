/**
 * @file src/bin2llvmir/optimizations/type_conversions/type_conversions.cpp
 * @brief Removes unnecessary data type conversions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/PatternMatch.h>

#include "retdec/bin2llvmir/optimizations/type_conversions/type_conversions.h"
#include "retdec/bin2llvmir/utils/debug.h"
#define debug_enabled false

using namespace llvm;
using namespace PatternMatch;

namespace retdec {
namespace bin2llvmir {

char TypeConversions::ID = 0;

static RegisterPass<TypeConversions> LLVMTestRegistered(
		"type-conversions",
		"Data type conversions optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

TypeConversions::TypeConversions() :
		ModulePass(ID),
		_module(nullptr)
{

}

bool TypeConversions::doInitialization(Module& M)
{
	_module = &M;
	return true;
}

bool TypeConversions::runOnModule(llvm::Module& M)
{
	bool changed = false;
	for (Function& F : M.functions())
	{
		changed |= runOnFunction(F);
	}
	return changed;
}

bool TypeConversions::runOnFunction(Function& F)
{
	bool changed = false;
	for (auto it = inst_begin(&F), eIt = inst_end(&F); it != eIt;)
	{
		Value* insn = &*it;
		++it;

		while (insn)
		{
			insn = opt(insn);
			changed |= insn != nullptr;
		}
	}
	return changed;
}

llvm::Value* TypeConversions::opt(llvm::Value* insn)
{
	auto* cast2 = dyn_cast<CastInst>(insn);
	auto* cast1 = cast2 ? dyn_cast<CastInst>(cast2->getOperand(0)) : nullptr;

	while (cast1)
	{
		if (auto* v = optCasts(cast1, cast2))
		{
			return v;
		}
		cast1 = dyn_cast<CastInst>(cast1->getOperand(0));
	}

	return nullptr;
}

llvm::Value* TypeConversions::optCasts(llvm::CastInst* cast1, llvm::CastInst* cast2)
{
	auto* src = cast1->getOperand(0);
	auto* srcTy = cast1->getSrcTy();
	auto* dstTy = cast2->getDestTy();

	Value* v = nullptr;

	// int -> cast -> cast -> int
	if (srcTy->isIntegerTy() && dstTy->isIntegerTy())
	{
		bool sign = cast1->getOpcode() == Instruction::SIToFP
				|| cast2->getOpcode() == Instruction::FPToSI;
		v = srcTy != dstTy
				? CastInst::CreateIntegerCast(src, dstTy, sign, "", cast2)
				: src;
	}
	// ptr -> cast -> cast -> ptr
	else if (srcTy->isPointerTy() && dstTy->isPointerTy())
	{
		v = srcTy != dstTy
				? CastInst::CreatePointerCast(src, dstTy, "", cast2)
				: src;
	}
	// float -> cast -> cast -> float
	else if (srcTy->isFloatingPointTy() && dstTy->isFloatingPointTy())
	{
		v = srcTy != dstTy
				? CastInst::CreateFPCast(src, dstTy, "", cast2)
				: src;
	}
	else
	{
		return nullptr;
	}

	cast2->replaceAllUsesWith(v);
	cast2->eraseFromParent();
	if (cast1->user_empty())
	{
		cast1->eraseFromParent();
	}
	return v;
}

} // namespace bin2llvmir
} // namespace retdec
