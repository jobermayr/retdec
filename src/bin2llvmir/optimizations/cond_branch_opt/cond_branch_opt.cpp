/**
* @file src/bin2llvmir/optimizations/cond_branch_opt/cond_branch_opt.cpp
* @brief Conditional branch optimization.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Operator.h>

#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/optimizations/cond_branch_opt/cond_branch_opt.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/symbolic_tree_match.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace llvm;
using namespace retdec::bin2llvmir::st_match;

namespace retdec {
namespace bin2llvmir {

char CondBranchOpt::ID = 0;

static RegisterPass<CondBranchOpt> X(
		"cond-branch-opt",
		"Conditional branch optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

CondBranchOpt::CondBranchOpt() :
		ModulePass(ID)
{

}

bool CondBranchOpt::runOnModule(llvm::Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	return run();
}

bool CondBranchOpt::runOnModuleCustom(llvm::Module& m, Config* c)
{
	_module = &m;
	_config = c;
	return run();
}

bool CondBranchOpt::run()
{
	if (_config == nullptr)
	{
		return false;
	}

	bool changed = false;

	ReachingDefinitionsAnalysis RDA;
	RDA.runOnModule(*_module, _config, true);

	for (Function& f : *_module)
	for (auto it = inst_begin(&f), eIt = inst_end(&f); it != eIt;)
	{
		Instruction& insn = *it;
		++it;

		changed |= runOnInstruction(RDA, insn);
	}

	return changed;
}

bool CondBranchOpt::runOnInstruction(
		ReachingDefinitionsAnalysis& RDA,
		llvm::Instruction& i)
{
	auto* br = dyn_cast<BranchInst>(&i);
	if (br == nullptr || br->isUnconditional())
	{
		return false;
	}
	auto* cond = br->getCondition();

	LOG << llvmObjToString(br) << std::endl;

	SymbolicTree root(RDA, cond);
	LOG << root << std::endl;

	root.removeGeneralRegisterLoads(_config);
	root.removeStackLoads(_config);
	LOG << root << std::endl;

	root.simplifyNode(_config);
	LOG << root << std::endl;

	Value* testedVal = nullptr;
	Value* subVal = nullptr;
	Instruction* binOp = nullptr;

	// for-simple.c -a arm -f elf -c gcc -C -O0
	//
	//>|   %_b_85d0 = or i1 %u0_subinst_153_85d0, %u3_subinst_153_85d0
	//		>|   %u16_85cc = icmp eq i32 %u10_85cc, 99
	//				>|   %u10_85cc = load i32, i32* @R3, align 4
	//				>| i32 99
	//		>|   %u3_subinst_153_85d0 = xor i1 %u1_subinst_153_85d0, %u2_subinst_153_85d0
	//				>|   %u15_85cc = icmp slt i32 %u11_85cc, 0
	//						>|   %u11_85cc = add i32 %u10_85cc, -99
	//								>|   %u10_85cc = load i32, i32* @R3, align 4
	//								>| i32 -99
	//						>| i32 0
	//				>|   %u14_85cc = icmp slt i32 %and_aab_0_85cc, 0
	//						>|   %and_aab_0_85cc = and i32 %5, %u10_85cc
	//								>|   %5 = sub i32 98, %u10_85cc
	//										>| i32 98
	//										>|   %u10_85cc = load i32, i32* @R3, align 4
	//								>|   %u10_85cc = load i32, i32* @R3, align 4
	//						>| i32 0
	//
	// ZF SF OF xor or
	// ZF OF SF xor or
	// SF OF xor ZF or
	// OF SF xor ZF or
	//
	// => icmp sle
	//
	// or X Y
	//
// ZF = icmp eq (val - X) 0
if (match(root, m_c_Or(
		m_CombineOr(
				m_c_Xor(m_Instruction<ICmpInst>(), m_Instruction<ICmpInst>()),
				m_c_ICmp(ICmpInst::ICMP_NE, m_Instruction<ICmpInst>(), m_Instruction<ICmpInst>())),
		m_c_ICmp(ICmpInst::ICMP_EQ,
				m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
				m_Zero()))))
{
	auto it = inst_begin(br->getFunction());
	assert(it != inst_end(br->getFunction()));
	auto* firstI = &*it;

	auto* testedA = new AllocaInst(
			testedVal->getType(),
			"",
			firstI);
	new StoreInst(testedVal, testedA, binOp);

	auto* subA = new AllocaInst(
			subVal->getType(),
			"",
			firstI);
	new StoreInst(subVal, subA, binOp);

	auto* testedL = new LoadInst(testedA, "", br);
	auto* subL = new LoadInst(subA, "", br);
	auto* conv = convertValueToType(testedL, subL->getType(), br);

	if (!conv->getType()->isIntegerTy() || !subL->getType()->isIntegerTy())
	{
		return false;
	}

	auto* newCond = new ICmpInst(
			br,
			ICmpInst::ICMP_SLE,
			conv,
			subL);

	LOG << "---" << llvmObjToString(br) << std::endl;

	br->replaceUsesOfWith(cond, newCond);

	LOG << "+++" << llvmObjToString(newCond) << std::endl;
	LOG << "+++" << llvmObjToString(br) << std::endl;
	return true;
}

ICmpInst* icmp = nullptr;
if (match(root, m_c_Or(
		m_CombineOr(
				m_c_Xor(m_Instruction<ICmpInst>(), m_Instruction<ICmpInst>()),
				m_c_ICmp(ICmpInst::ICMP_NE, m_Instruction<ICmpInst>(), m_Instruction<ICmpInst>())),
		m_c_ICmp(ICmpInst::ICMP_EQ,
				m_Value(testedVal),
				m_Value(subVal),
				&icmp))))
{
	auto it = inst_begin(br->getFunction());
	assert(it != inst_end(br->getFunction()));
	auto* firstI = &*it;

	auto* testedA = new AllocaInst(
			testedVal->getType(),
			"",
			firstI);
	new StoreInst(testedVal, testedA, icmp);

	auto* subA = new AllocaInst(
			subVal->getType(),
			"",
			firstI);
	new StoreInst(subVal, subA, icmp);

	auto* testedL = new LoadInst(testedA, "", br);
	auto* subL = new LoadInst(subA, "", br);
	auto* conv = convertValueToType(testedL, subL->getType(), br);

	if (!conv->getType()->isIntegerTy() || !subL->getType()->isIntegerTy())
	{
		return false;
	}

	auto* newCond = new ICmpInst(
			br,
			ICmpInst::ICMP_SLE,
			conv,
			subL);

	LOG << "---" << llvmObjToString(br) << std::endl;

	br->replaceUsesOfWith(cond, newCond);

	LOG << "+++" << llvmObjToString(newCond) << std::endl;
	LOG << "+++" << llvmObjToString(br) << std::endl;

	LOG << "===========> OK" << std::endl;
	return true;
}

	// for-simple.c -a x86 -f elf -c gcc -C -O0
	//
	//>|   %_b_804861a = xor i1 %u0_subinst_203_804861a, %u1_subinst_203_804861a
	//		>|   %u1_subinst_202_8048617 = icmp slt i32 %u9_8048617, 0
	//				>|   %u9_8048617 = sub i32 %7, %u5_8048617
	//						>|   %7 = load i32, i32* %stack_var_-16
	//						>|   %u5_8048617 = load i32, i32* @eax, align 4
	//				>| i32 0
	//		>|   %u8_8048617 = icmp slt i32 %and_aab_1_8048617, 0
	//				>|   %and_aab_1_8048617 = and i32 %xor_aab_1_8048617, %xor_ab_1_8048617
	//						>|   %xor_aab_1_8048617 = xor i32 %sub_ab_1_8048617, %7
	//								>|   %sub_ab_1_8048617 = sub i32 %7, %u5_8048617
	//										>|   %7 = load i32, i32* %stack_var_-16
	//										>|   %u5_8048617 = load i32, i32* @eax, align 4
	//								>|   %7 = load i32, i32* %stack_var_-16
	//						>|   %xor_ab_1_8048617 = xor i32 %u5_8048617, %7
	//								>|   %u5_8048617 = load i32, i32* @eax, align 4
	//								>|   %7 = load i32, i32* %stack_var_-16
	//				>| i32 0
	//
	// SF OF xor
	// OF SF xor
	//
	// => icmp slt
	//
if (match(root, m_c_Xor(
		m_c_ICmp(ICmpInst::ICMP_SLT,
				m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
				m_Zero()),
		m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Zero())))
	// TODO: the same, but starts with ICMP NE, instead of XOR.
	|| match(root, m_c_ICmp(ICmpInst::ICMP_NE,
		m_c_ICmp(ICmpInst::ICMP_SLT,
				m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
				m_Zero()),
		m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Zero()))))
{
	auto it = inst_begin(br->getFunction());
	assert(it != inst_end(br->getFunction()));
	auto* firstI = &*it;

	auto* testedA = new AllocaInst(
			testedVal->getType(),
			"",
			firstI);
	new StoreInst(testedVal, testedA, binOp);

	auto* subA = new AllocaInst(
			subVal->getType(),
			"",
			firstI);
	new StoreInst(subVal, subA, binOp);

	auto* testedL = new LoadInst(testedA, "", br);
	auto* subL = new LoadInst(subA, "", br);
	auto* conv = convertValueToType(testedL, subL->getType(), br);

	if (!conv->getType()->isIntegerTy() || !subL->getType()->isIntegerTy())
	{
		return false;
	}

	auto* newCond = new ICmpInst(
			br,
			ICmpInst::ICMP_SLT,
			conv,
			subL);

	LOG << "---" << llvmObjToString(br) << std::endl;

	br->replaceUsesOfWith(cond, newCond);

	LOG << "+++" << llvmObjToString(newCond) << std::endl;
	LOG << "+++" << llvmObjToString(br) << std::endl;
	return true;
}

	// for-simple.c -a x86 -f pe -c gcc -C -O0
	//
	//>|   %77 = and i1 %76, %75
	//	>|   %76 = icmp eq i1 %72, false
	//		>|   %66 = icmp eq i32 %56, 0
	//			>|   %56 = sub i32 %51, %55
	//				>|   %51 = load i32, i32* @eax, align 4
	//				>|   %55 = load i32, i32* %stack_var_-16
	//			>| i32 0
	//		>| i1 false
	//	>|   %75 = icmp eq i1 %73, %74
	//		>|   %67 = icmp slt i32 %56, 0
	//			>|   %56 = sub i32 %51, %55
	//			>| i32 0
	//		>|   %65 = icmp slt i32 %64, 0
	//			>|   %64 = and i32 %63, %62
	//				>|   %63 = xor i32 %56, %51
	//					>|   %56 = sub i32 %51, %55
	//					>|   %51 = load i32, i32* @eax, align 4
	//				>|   %62 = xor i32 %55, %51
	//					>|   %55 = load i32, i32* %stack_var_-16
	//					>|   %51 = load i32, i32* @eax, align 4
	//			>| i32 0
	//
if (match(root, m_c_And(
		m_c_ICmp(ICmpInst::ICMP_EQ,
				m_c_ICmp(ICmpInst::ICMP_EQ, m_Value(), m_Value()),
				m_Zero()),
		m_c_ICmp(ICmpInst::ICMP_EQ,
				m_c_ICmp(ICmpInst::ICMP_SLT,
						m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
						m_Value()),
				m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value())))))
{
	auto it = inst_begin(br->getFunction());
	assert(it != inst_end(br->getFunction()));
	auto* firstI = &*it;

	auto* testedA = new AllocaInst(
			testedVal->getType(),
			"",
			firstI);
	new StoreInst(testedVal, testedA, binOp);

	auto* subA = new AllocaInst(
			subVal->getType(),
			"",
			firstI);
	new StoreInst(subVal, subA, binOp);

	auto* testedL = new LoadInst(testedA, "", br);
	auto* subL = new LoadInst(subA, "", br);
	auto* conv = convertValueToType(testedL, subL->getType(), br);

	if (!conv->getType()->isIntegerTy() || !subL->getType()->isIntegerTy())
	{
		return false;
	}

	auto* newCond = new ICmpInst(
			br,
			ICmpInst::ICMP_SGT,
			conv,
			subL);

	LOG << "---" << llvmObjToString(br) << std::endl;

	br->replaceUsesOfWith(cond, newCond);

	LOG << "+++" << llvmObjToString(newCond) << std::endl;
	LOG << "+++" << llvmObjToString(br) << std::endl;
	return true;
}

	// for-simple.c -a x86 -f elf -c gcc -C -O0
	//
	//>|   %_b_8048688 = xor i1 %u4_subinst_316_8048688, true
	//		>|   %u4_subinst_316_8048688 = or i1 %u3_subinst_316_8048688, %u2_subinst_316_8048688
	//				>|   %u3_subinst_316_8048688 = xor i1 %u0_subinst_316_8048688, %u1_subinst_316_8048688
	//						>|   %u1_subinst_315_8048685 = icmp slt i32 %u9_8048685, 0
	//								>|   %u9_8048685 = sub i32 %u4_8048685, %9
	//										>|   %u4_8048685 = load i32, i32* @eax, align 4
	//										>|   %9 = load i32, i32* %stack_var_-16
	//								>| i32 0
	//						>|   %u8_8048685 = icmp slt i32 %and_aab_1_8048685, 0
	//								>|   %and_aab_1_8048685 = and i32 %xor_aab_1_8048685, %xor_ab_1_8048685
	//										>|   %xor_aab_1_8048685 = xor i32 %sub_ab_1_8048685, %u4_8048685
	//												>|   %sub_ab_1_8048685 = sub i32 %u4_8048685, %9
	//														>|   %u4_8048685 = load i32, i32* @eax, align 4
	//														>|   %9 = load i32, i32* %stack_var_-16
	//												>|   %u4_8048685 = load i32, i32* @eax, align 4
	//										>|   %xor_ab_1_8048685 = xor i32 %9, %u4_8048685
	//												>|   %9 = load i32, i32* %stack_var_-16
	//												>|   %u4_8048685 = load i32, i32* @eax, align 4
	//								>| i32 0
	//				>|   %u0_subinst_315_8048685 = icmp eq i32 %u9_8048685, 0
	//						>|   %u9_8048685 = sub i32 %u4_8048685, %9
	//						>| i32 0
	//		>| i1 true
	//
	// for-simple.c -a arm -f elf -c gcc -C -O0
	//
	//>|   %_b_87c8 = xor i1 %u4_subinst_248_87c8, true
	//		>|   %u4_subinst_248_87c8 = or i1 %u0_subinst_248_87c8, %u3_subinst_248_87c8
	//				>|   %u10_87c4 = icmp eq i32 %u4_87c4, %u1_87c4
	//						>|   %u4_87c4 = load i32, i32* @R2, align 4
	//						>|   %u1_87c4 = load i32, i32* @R3, align 4
	//				>|   %u3_subinst_248_87c8 = xor i1 %u1_subinst_248_87c8, %u2_subinst_248_87c8
	//						>|   %u9_87c4 = icmp slt i32 %u5_87c4, 0
	//								>|   %u5_87c4 = sub i32 %u4_87c4, %u1_87c4
	//										>|   %u4_87c4 = load i32, i32* @R2, align 4
	//										>|   %u1_87c4 = load i32, i32* @R3, align 4
	//								>| i32 0
	//						>|   %u8_87c4 = icmp slt i32 %and_aab_0_87c4, 0
	//								>|   %and_aab_0_87c4 = and i32 %xor_aab_0_87c4, %xor_ab_0_87c4
	//										>|   %xor_aab_0_87c4 = xor i32 %sub_ab_0_87c4, %u4_87c4
	//												>|   %sub_ab_0_87c4 = sub i32 %u4_87c4, %u1_87c4
	//														>|   %u4_87c4 = load i32, i32* @R2, align 4
	//														>|   %u1_87c4 = load i32, i32* @R3, align 4
	//												>|   %u4_87c4 = load i32, i32* @R2, align 4
	//										>|   %xor_ab_0_87c4 = xor i32 %u4_87c4, %u1_87c4
	//												>|   %u4_87c4 = load i32, i32* @R2, align 4
	//												>|   %u1_87c4 = load i32, i32* @R3, align 4
	//								>| i32 0
	//		>| i1 true
	//
	// ZF SF OF xor or 1 xor
	// ZF OF SF xor or 1 xor
	// SF OF xor ZF or 1 xor
	// OF SF xor ZF or 1 xor
	//
	// => icmp sgt
	//
if (match(root, m_c_Xor(
		m_c_Or(
				m_c_Xor(
						m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value()),
						m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value())),
				m_c_ICmp(ICmpInst::ICMP_EQ,
						m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
						m_Zero())),
		m_One())))
{
	auto it = inst_begin(br->getFunction());
	assert(it != inst_end(br->getFunction()));
	auto* firstI = &*it;

	auto* testedA = new AllocaInst(
			testedVal->getType(),
			"",
			firstI);
	new StoreInst(testedVal, testedA, binOp);

	auto* subA = new AllocaInst(
			subVal->getType(),
			"",
			firstI);
	new StoreInst(subVal, subA, binOp);

	auto* testedL = new LoadInst(testedA, "", br);
	auto* subL = new LoadInst(subA, "", br);
	auto* conv = convertValueToType(testedL, subL->getType(), br);

	if (!conv->getType()->isIntegerTy() || !subL->getType()->isIntegerTy())
	{
		return false;
	}

	auto* newCond = new ICmpInst(
			br,
			ICmpInst::ICMP_SGT,
			conv,
			subL);

	LOG << "---" << llvmObjToString(br) << std::endl;

	br->replaceUsesOfWith(cond, newCond);

	LOG << "+++" << llvmObjToString(newCond) << std::endl;
	LOG << "+++" << llvmObjToString(br) << std::endl;
	return true;
}

if (match(root, m_c_Xor(
		m_c_Or(
				m_c_Xor(
						m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value()),
						m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value())),
				m_c_ICmp(ICmpInst::ICMP_EQ,
						m_Value(testedVal),
						m_Value(subVal),
						&icmp)),
		m_One())))
{
	auto it = inst_begin(br->getFunction());
	assert(it != inst_end(br->getFunction()));
	auto* firstI = &*it;

	auto* testedA = new AllocaInst(
			testedVal->getType(),
			"",
			firstI);
	new StoreInst(testedVal, testedA, icmp);

	auto* subA = new AllocaInst(
			subVal->getType(),
			"",
			firstI);
	new StoreInst(subVal, subA, icmp);

	auto* testedL = new LoadInst(testedA, "", br);
	auto* subL = new LoadInst(subA, "", br);
	auto* conv = convertValueToType(testedL, subL->getType(), br);

	if (!conv->getType()->isIntegerTy() || !subL->getType()->isIntegerTy())
	{
		return false;
	}

	auto* newCond = new ICmpInst(
			br,
			ICmpInst::ICMP_SGT,
			conv,
			subL);

	LOG << "---" << llvmObjToString(br) << std::endl;

	br->replaceUsesOfWith(cond, newCond);

	LOG << "+++" << llvmObjToString(newCond) << std::endl;
	LOG << "+++" << llvmObjToString(br) << std::endl;
	return true;
}

	// for-simple.c -a x86 -f elf -c clang -C -O0
	//
	//>|   %_b_8048584 = xor i1 %tmp_subinst_62_8048584, true
	//		>|   %tmp_subinst_62_8048584 = xor i1 %u0_subinst_62_8048584, %u1_subinst_62_8048584
	//				>|   %u1_subinst_61_804857d = icmp slt i32 %u9_804857d, 0
	//						>|   %u9_804857d = add i32 %4, -100
	//								>|   %4 = load i32, i32* %stack_var_-8
	//								>| i32 -100
	//						>| i32 0
	//				>|   %u8_804857d = icmp slt i32 %and_aab_1_804857d, 0
	//						>|   %and_aab_1_804857d = and i32 %5, %4
	//								>|   %5 = sub i32 99, %4
	//										>| i32 99
	//										>|   %4 = load i32, i32* %stack_var_-8
	//								>|   %4 = load i32, i32* %stack_var_-8
	//						>| i32 0
	//		>| i1 true
	//
	// 1 SF OF xor xor
	// 1 OF SF xor xor
	// SF OF xor 1 xor
	// OF SF xor 1 xor
	//
	// => icmp sge
	//

if (match(root, m_c_Xor(
		m_c_Xor(
				m_c_ICmp(ICmpInst::ICMP_SLT,
						m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
						m_Zero()),
				m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value())),
		m_One()))
// TODO: the same, but starts with ICMP NE, instead of XOR.
	|| match(root, m_c_ICmp(ICmpInst::ICMP_NE,
		m_c_Xor(
				m_c_ICmp(ICmpInst::ICMP_SLT,
						m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
						m_Zero()),
				m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value())),
		m_One())))
{
	auto it = inst_begin(br->getFunction());
	assert(it != inst_end(br->getFunction()));
	auto* firstI = &*it;

	auto* testedA = new AllocaInst(
			testedVal->getType(),
			"",
			firstI);
	new StoreInst(testedVal, testedA, binOp);

	auto* subA = new AllocaInst(
			subVal->getType(),
			"",
			firstI);
	new StoreInst(subVal, subA, binOp);

	auto* testedL = new LoadInst(testedA, "", br);
	auto* subL = new LoadInst(subA, "", br);
	auto* conv = convertValueToType(testedL, subL->getType(), br);

	if (!conv->getType()->isIntegerTy() || !subL->getType()->isIntegerTy())
	{
		return false;
	}

	auto* newCond = new ICmpInst(
			br,
			ICmpInst::ICMP_SGE,
			conv,
			subL);

	LOG << "---" << llvmObjToString(br) << std::endl;

	br->replaceUsesOfWith(cond, newCond);

	LOG << "+++" << llvmObjToString(newCond) << std::endl;
	LOG << "+++" << llvmObjToString(br) << std::endl;
	return true;
}

	// for-simple.c -a x86 -f elf -c clang -C -O0
	//
	//>|   %50 = icmp eq i1 %48, %49
	//	>|   %43 = icmp slt i32 %32, 0
	//		>|   %32 = sub i32 %30, %31
	//			>|   %30 = load i32, i32* @eax, align 4
	//			>|   %31 = load i32, i32* inttoptr (i32 134519620 to i32*), align 4
	//				>| i32 134519620
	//		>| i32 0
	//	>|   %41 = icmp slt i32 %40, 0
	//		>|   %40 = and i32 %39, %38
	//			>|   %39 = xor i32 %32, %30
	//				>|   %32 = sub i32 %30, %31
	//				>|   %30 = load i32, i32* @eax, align 4
	//			>|   %38 = xor i32 %31, %30
	//				>|   %31 = load i32, i32* inttoptr (i32 134519620 to i32*), align 4
	//				>|   %30 = load i32, i32* @eax, align 4
	//		>| i32 0
	//
	// => icmp sge
	//

if (match(root, m_c_ICmp(ICmpInst::ICMP_EQ,
		m_c_ICmp(ICmpInst::ICMP_SLT,
				m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
				m_Zero()),
		m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value()))))
{
	auto it = inst_begin(br->getFunction());
	assert(it != inst_end(br->getFunction()));
	auto* firstI = &*it;

	auto* testedA = new AllocaInst(
			testedVal->getType(),
			"",
			firstI);
	new StoreInst(testedVal, testedA, binOp);

	auto* subA = new AllocaInst(
			subVal->getType(),
			"",
			firstI);
	new StoreInst(subVal, subA, binOp);

	auto* testedL = new LoadInst(testedA, "", br);
	auto* subL = new LoadInst(subA, "", br);
	auto* conv = convertValueToType(testedL, subL->getType(), br);

	if (!conv->getType()->isIntegerTy() || !subL->getType()->isIntegerTy())
	{
		return false;
	}

	auto* newCond = new ICmpInst(
			br,
			ICmpInst::ICMP_SGE,
			conv,
			subL);

	LOG << "---" << llvmObjToString(br) << std::endl;

	br->replaceUsesOfWith(cond, newCond);

	LOG << "+++" << llvmObjToString(newCond) << std::endl;
	LOG << "+++" << llvmObjToString(br) << std::endl;
	return true;
}

	// for-simple.c -a x86 -f elf -c clang -C -O0
	//
	//>|   %_b_80488f7 = xor i1 %u0_subinst_300_80488f7, true
	//		>|   %u0_subinst_299_80488f5 = icmp eq i32 %u5_80488f5, 0
	//				>|   %u5_80488f5 = sub i32 %u0_80488f5, %u1_80488f5
	//						>|   %u0_80488f5 = load i32, i32* @edi, align 4
	//						>|   %u1_80488f5 = load i32, i32* @esi, align 4
	//				>| i32 0
	//		>| i1 true
	//
	// 1 ZF xor
	// ZF 1 xor
	//
	// => icmp ne
	//
if (match(root, m_c_Xor(
		m_c_ICmp(ICmpInst::ICMP_EQ,
				m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
				m_Zero()),
		m_One()))
	// TODO: the same, but starts with ICMP NE, instead of XOR.
	|| match(root, m_c_ICmp(ICmpInst::ICMP_NE,
		m_c_ICmp(ICmpInst::ICMP_EQ,
				m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
				m_Zero()),
		m_One())))
{
	auto it = inst_begin(br->getFunction());
	assert(it != inst_end(br->getFunction()));
	auto* firstI = &*it;

	auto* testedA = new AllocaInst(
			testedVal->getType(),
			"",
			firstI);
	new StoreInst(testedVal, testedA, binOp);

	auto* subA = new AllocaInst(
			subVal->getType(),
			"",
			firstI);
	new StoreInst(subVal, subA, binOp);

	auto* testedL = new LoadInst(testedA, "", br);
	auto* subL = new LoadInst(subA, "", br);
	auto* conv = convertValueToType(testedL, subL->getType(), br);

	if (!conv->getType()->isIntegerTy() || !subL->getType()->isIntegerTy())
	{
		return false;
	}

	auto* newCond = new ICmpInst(
			br,
			ICmpInst::ICMP_NE,
			conv,
			subL);

	LOG << "---" << llvmObjToString(br) << std::endl;

	br->replaceUsesOfWith(cond, newCond);

	LOG << "+++" << llvmObjToString(newCond) << std::endl;
	LOG << "+++" << llvmObjToString(br) << std::endl;
	return true;
}

	// >|   %cond_aux0_8260 = xor i1 %u0_8260, true
	// >|   %caddc_res1_1_825e = icmp ugt i32 %u3_825e, 2
	//         >|   %u3_825e = load i32, i32* @R3, align 4
	//         >| i32 2
	// >| i1 true
	//
llvm::LoadInst* load = nullptr;
ConstantInt* ci = nullptr;
if (match(root, m_c_Xor(
		m_c_ICmp(ICmpInst::ICMP_UGT,
				m_Load(m_Value(), &load),
				m_ConstantInt(ci)),
		m_One()))
	// TODO: the same, but starts with ICMP NE, instead of XOR.
	|| match(root, m_c_ICmp(ICmpInst::ICMP_NE,
		m_c_ICmp(ICmpInst::ICMP_UGT,
				m_Load(m_Value(), &load),
				m_ConstantInt(ci)),
		m_One())))
{
	auto* r = load->getPointerOperand();
	auto* nl = new LoadInst(r, "", br);
	// For some reason, this is not working.
	//
//		auto* nci = ConstantInt::get(nl->getType(), ci->getZExtValue());
//		auto* icmp = new ICmpInst(br, ICmpInst::ICMP_ULE, nl, nci);
	auto* nci = ConstantInt::get(nl->getType(), ci->getZExtValue() - 1);

	if (!nl->getType()->isIntegerTy() || !nci->getType()->isIntegerTy())
	{
		return false;
	}

	auto* icmp = new ICmpInst(br, ICmpInst::ICMP_ULT, nl, nci);
	br->replaceUsesOfWith(cond, icmp);
	return true;
}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
