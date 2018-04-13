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

} // namespace bin2llvmir
} // namespace retdec
