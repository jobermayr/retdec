/**
 * @file src/bin2llvmir/optimizations/inst_opt/inst_opt.cpp
 * @brief Optimize a single LLVM instruction.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/PatternMatch.h>

#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h"

using namespace llvm;
using namespace PatternMatch;

namespace retdec {
namespace bin2llvmir {
namespace inst_opt {

//void addZero(llvm::Instruction* insn)
//{
//	if (isa<AddOperator>(insn) || isa<SubOperator>(insn))
//	{
//		auto* bin = dyn_cast<BinaryOperator>(insn);
//
//		auto* c0 = dyn_cast<ConstantInt>(bin->getOperand(0));
//		auto* c1 = dyn_cast<ConstantInt>(bin->getOperand(1));
//
//		if (c0 && c0->isZero() && isa<AddOperator>(insn))
//		{
//			bin->replaceAllUsesWith(bin->getOperand(1));
//			bin->eraseFromParent();
//		}
//		else if (c1 && c1->isZero())
//		{
//			bin->replaceAllUsesWith(bin->getOperand(0));
//			bin->eraseFromParent();
//		}
//	}
//}

llvm::Instruction* subZero(llvm::Instruction* insn)
{
	ConstantInt* op1;
	uint64_t zero = 0;

	if (!match(insn, m_Sub(m_Value(), m_ConstantInt(val))))
	{
		return insn;
	}

//	auto* sub = dyn_cast<SubOperator>(insn);
//	auto* ci =
//	if (sub == nullptr)
//	{
//		return insn;
//	}

	return insn;
}

bool optimize(llvm::Instruction* insn)
{
	bool changed = false;

//	changed |= optimize_stosX(ai, ci, xi);
//	changed |= optimize_cmpsX(ai, ci, xi);
//	changed |= optimize_movsX(ai, ci, xi);
//	changed |= optimize_scasX(ai, ci, xi);

	return changed;
}

} // namespace inst_opt
} // namespace bin2llvmir
} // namespace retdec

//	// TODO: Maybe capstone2llvmir could/should generate code like this
//	// out of the box.
//	if (auto* zext = dyn_cast<ZExtInst>(insn))
//	{
//		auto* trunc = dyn_cast<TruncInst>(zext->getOperand(0));
//		if (trunc
//				&& trunc->getSrcTy()->isIntegerTy(32)
//				&& trunc->getDestTy()->isIntegerTy(8)
//				&& zext->getSrcTy()->isIntegerTy(8)
//				&& zext->getDestTy()->isIntegerTy(32))
//		{
//			auto* a = BinaryOperator::CreateAnd(
//					trunc->getOperand(0),
//					ConstantInt::get(trunc->getOperand(0)->getType(), 255),
//					"",
//					zext);
//			zext->replaceAllUsesWith(a);
//			zext->eraseFromParent();
//			if (trunc->user_empty())
//			{
//				trunc->eraseFromParent();
//			}
//		}
//		else if (trunc
//				&& trunc->getSrcTy()->isIntegerTy(32)
//				&& trunc->getDestTy()->isIntegerTy(16)
//				&& zext->getSrcTy()->isIntegerTy(16)
//				&& zext->getDestTy()->isIntegerTy(32))
//		{
//			auto* a = BinaryOperator::CreateAnd(
//					trunc->getOperand(0),
//					ConstantInt::get(trunc->getOperand(0)->getType(), 65535),
//					"",
//					zext);
//			zext->replaceAllUsesWith(a);
//			zext->eraseFromParent();
//			if (trunc->user_empty())
//			{
//				trunc->eraseFromParent();
//			}
//		}

//bool InstructionOptimizer::runGeneralOpts()
//{
//	bool changed = false;
//
//	for (auto& F : _module->getFunctionList())
//	{
//		for (auto ai = AsmInstruction(&F); ai.isValid(); ai = ai.getNext())
//		{
//			std::set<Instruction*> toErase;
//
//			for (auto& i : ai)
//			{
//				if (!isa<BinaryOperator>(i))
//				{
//					continue;
//				}
//
//				auto* op0 = dyn_cast<LoadInst>(i.getOperand(0));
//				auto* op1 = dyn_cast<LoadInst>(i.getOperand(1));
//				if (!(op0 && op1 && op0->getPointerOperand() == op1->getPointerOperand()))
//				{
//					continue;
//				}
//				AsmInstruction op0Asm(op0);
//				AsmInstruction op1Asm(op1);
//				if ((op0Asm != op1Asm) || (op0Asm != ai))
//				{
//					continue;
//				}
//
//				if (i.getOpcode() == Instruction::Xor)
//				{
//					i.replaceAllUsesWith(ConstantInt::get(i.getType(), 0));
//					toErase.insert(&i);
//					if (op0 != op1)
//					{
//						op1->replaceAllUsesWith(op0);
//						toErase.insert(op1);
//					}
//					changed = true;
//				}
//				else if (i.getOpcode() == Instruction::Or
//						|| i.getOpcode() == Instruction::And)
//				{
//					i.replaceAllUsesWith(op0);
//					toErase.insert(&i);
//					if (op0 != op1)
//					{
//						op1->replaceAllUsesWith(op0);
//						toErase.insert(op1);
//					}
//					changed = true;
//				}
//			}
//
//			for (auto* i : toErase)
//			{
//				i->eraseFromParent();
//				changed = true;
//			}
//		}
//	}
//
//	return changed;
//}
