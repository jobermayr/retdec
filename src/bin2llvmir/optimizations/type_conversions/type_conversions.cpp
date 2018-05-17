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
			insn = experimental(insn);
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

/**
 * %ptr  = alloca i32
 * %int  = ptrtoint i32* %ptr to i32
 * %ptr2 = inttoptr i32 %int to i32*
 *
 * =>
 *
 *
 */
bool TypeConversions::removePtrToIntToPtr(llvm::Instruction* instr)
{
	if (!(isa<IntToPtrInst>(instr) && isa<PtrToIntInst>(instr->getOperand(0))))
		return false;

	auto* p2i = dyn_cast<PtrToIntInst>(instr->getOperand(0));
	auto* bc = BitCastInst::CreatePointerCast(
			p2i->getOperand(0),
			instr->getType(),
			"",
			instr);
	instr->replaceAllUsesWith(bc);
	instr->eraseFromParent();
	if (p2i->getNumUses() == 0)
		p2i->eraseFromParent();
	return true;
}

bool TypeConversions::runInInstruction(Instruction* start)
{
	return false;

	if (!start->isCast())
	{
		return false;
	}

	LOG << "|> " << llvmObjToString(start) << std::endl;

	Instruction* prev = start;
	unsigned cntr = 0;
	Instruction* lastGood = nullptr;

	while (prev && prev->isCast())
	{
		Value* castSrc = nullptr;
		if (prev->getNumOperands() > 0)
			castSrc = prev->getOperand(0);

		LOG << "\t|> " << llvmObjToString(prev) << std::endl;

		if (castSrc)
		{
			LOG << "\t\t|> " << llvmObjToString(castSrc) << std::endl;

			++cntr;
			if ( (start->getType()->isFloatingPointTy() &&
					castSrc->getType()->isFloatingPointTy()) ||
				 (start->getType()->isIntegerTy() &&
					castSrc->getType()->isIntegerTy()))
			{
				lastGood = dyn_cast<Instruction>(castSrc);
			}

			if (Argument* arg = dyn_cast<Argument>(castSrc))
			{
				if (arg->getType() == start->getType() && start->getNumUses())
				{
					LOG << "\t|> arg: " << llvmObjToString(arg) << std::endl;
					start->replaceAllUsesWith(arg);
					start->eraseFromParent();
					return true;
				}
			}

			else if (GlobalVariable* glob = dyn_cast<GlobalVariable>(castSrc))
			{
				if (glob->getType() == start->getType() && start->getNumUses())
				{
					LOG << "\t|> global: " << llvmObjToString(glob) << std::endl;
					start->replaceAllUsesWith(glob);
					start->eraseFromParent();
					return true;
				}
			}

			else if (Instruction* inst = dyn_cast<Instruction>(castSrc))
			{
				if (inst != start
						&& start->getNumUses()
						&& inst->getParent() == start->getParent()
						&& inst->getType() == start->getType())
				{
					LOG << "\t|> inst: " << llvmObjToString(inst) << std::endl;
					start->replaceAllUsesWith(inst);
					start->eraseFromParent();
					return true;
				}
			}

			if (prev->getOpcode() != Instruction::FPToSI
				&& prev->getOpcode() != Instruction::FPToUI
				&& prev->getOpcode() != Instruction::UIToFP
				&& prev->getOpcode() != Instruction::SIToFP)
			{
				LOG << "\t|> prev: " << llvmObjToString(castSrc) << std::endl;
				prev = dyn_cast<Instruction>(castSrc);
			}
			else
			{
				return replaceByShortcut(start, lastGood, cntr);
			}
		}
		else
		{
			return replaceByShortcut(start, lastGood, cntr);
		}
	}

	return replaceByShortcut(start, lastGood, cntr);
}

bool TypeConversions::replaceByShortcut(
		Instruction* start,
		Instruction* lastGood,
		unsigned cntr)
{
	LOG << "replaceByShortcut() : "
		<< llvmObjToString(start) << " -> "
		<< llvmObjToString(lastGood) << std::endl;

	if (lastGood
			&& start->getNumUses()
			&& lastGood->getParent() == start->getParent())
	{
		if (start->getType()->isFloatingPointTy()
				&& !lastGood->getType()->isFloatingPointTy())
		{
			return false; // should not happen
		}
		if (start->getType()->isIntegerTy()
				&& !lastGood->getType()->isIntegerTy())
		{
			return false; // should not happen
		}

		// General type (int/float) of start and lastGood should be the same.
		//
		if (lastGood->getOpcode() == Instruction::SIToFP)
		{
			Instruction *n = new SIToFPInst(
					lastGood->getOperand(0),
					start->getType());
			n->insertBefore(start);
			start->replaceAllUsesWith(n);
			start->eraseFromParent();
			return true;
		}
		else if (lastGood->getOpcode() == Instruction::UIToFP)
		{
			Instruction *n = new UIToFPInst(
					lastGood->getOperand(0),
					start->getType());
			n->insertBefore(start);
			start->replaceAllUsesWith(n);
			start->eraseFromParent();
			return true;
		}
		else if (lastGood->getOpcode() == Instruction::FPToSI)
		{
			Instruction *n = new FPToSIInst(
					lastGood->getOperand(0),
					start->getType());
			n->insertBefore(start);
			start->replaceAllUsesWith(n);
			start->eraseFromParent();
			return true;
		}
		else if (lastGood->getOpcode() == Instruction::FPToUI)
		{
			Instruction *n = new FPToUIInst(
					lastGood->getOperand(0),
					start->getType());
			n->insertBefore(start);
			start->replaceAllUsesWith(n);
			start->eraseFromParent();
			return true;
		}
		else if (cntr>1 && start->getType()->isFloatingPointTy())
		{
			Instruction *n = CastInst::CreateFPCast(
					lastGood,
					start->getType());
			n->insertBefore(start);
			start->replaceAllUsesWith(n);
			start->eraseFromParent();
			// do not return true here
		}
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
