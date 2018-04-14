/**
* @file src/bin2llvmir/optimizations/decoder/arm.cpp
* @brief Decoding methods specific to ARM architecture.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/utils/capstone.h"
#include "retdec/utils/string.h"

using namespace retdec::utils;
using namespace retdec::capstone2llvmir;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

bool insnWrittesPc(csh& ce, cs_insn* insn)
{
	auto& arm = insn->detail->arm;

	// Implicit write.
	//
	if (cs_reg_read(ce, insn, ARM_REG_PC))
	{
		return true;
	}

	// Explicit write.
	//
	for (std::size_t i = 0; arm.op_count; ++i)
	{
		auto& op = arm.operands[i];
		if (op.type == ARM_OP_REG
				&& op.reg == ARM_REG_PC)
		{
			return true;
		}
	}

	return false;
}

std::size_t Decoder::decodeJumpTargetDryRun_arm(
		const JumpTarget& jt,
		ByteData bytes)
{
	static csh ce = _c2l->getCapstoneEngine();

	uint64_t addr = jt.getAddress();
	std::size_t nops = 0;
	bool first = true;
	while (cs_disasm_iter(ce, &bytes.first, &bytes.second, &addr, _dryCsInsn))
	{
		if (jt.getType() == JumpTarget::eType::LEFTOVER
				&& (first || nops > 0)
				&& capstone_utils::isNopInstruction(
						_config->getConfig().architecture,
						_dryCsInsn))
		{
			nops += _dryCsInsn->size;
		}
		else if (jt.getType() == JumpTarget::eType::LEFTOVER
				&& nops > 0)
		{
			return nops;
		}

		if (_c2l->isControlFlowInstruction(*_dryCsInsn)
				|| insnWrittesPc(ce, _dryCsInsn))
		{
			return false;
		}

		first = false;
	}

	if (nops > 0)
	{
		return nops;
	}

	// There is a BB right after, that is not a function start.
	//
	if (getBasicBlockAtAddress(addr) && getFunctionAtAddress(addr) == nullptr)
	{
		return false;
	}

	return true;
}

/**
 * Recognize some ARM-specific patterns.
 */
void Decoder::patternsPseudoCall_arm(llvm::CallInst*& call, AsmInstruction& ai)
{
	// TODO: We could detect this using architecture-agnostic approach by using
	// ABI info on LR reg.
	//
	// 113A0 0F E0 A0 E1    MOV LR, PC   // PC = current insn + 2*insn_size
	// 113A4 03 F0 A0 E1    MOV PC, R3   // branch -> call
	// 113A8 00 20 94 E5    LDR R2, [R4] // next insn = return point
	//
	// Check that both instructions have the same cond code:
	// 112E8 0F E0 A0 11    MOVNE LR, PC
	// 112EC 03 F0 A0 11    MOVNE PC, R3
	//
	if (_c2l->isBranchFunctionCall(call))
	{
		AsmInstruction prev = ai.getPrev();
		if (prev.isInvalid())
		{
			return;
		}
		auto* insn = ai.getCapstoneInsn();
		auto& arm = insn->detail->arm;
		auto* pInsn = prev.getCapstoneInsn();
		auto& pArm = pInsn->detail->arm;

		if (pInsn->id == ARM_INS_MOV
				&& arm.cc == pArm.cc
				&& pArm.op_count == 2
				&& pArm.operands[0].type == ARM_OP_REG
				&& pArm.operands[0].reg == ARM_REG_LR
				&& pArm.operands[1].type == ARM_OP_REG
				&& pArm.operands[1].reg == ARM_REG_PC)
		{
			// Replace pseudo branch with pseudo call.
			auto* nc = CallInst::Create(
					_c2l->getCallFunction(),
					{call->getArgOperand(0)},
					"",
					call);
			call->eraseFromParent();
			call = nc;
		}
//		; 0x113a0
	}
}

} // namespace bin2llvmir
} // namespace retdec
