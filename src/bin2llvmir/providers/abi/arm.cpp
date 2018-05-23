/**
 * @file src/bin2llvmir/providers/abi/arm.h
 * @brief ABI information for ARM.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/arm.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

AbiArm::AbiArm(llvm::Module* m, Config* c) :
		Abi(m, c)
{
	_regs.reserve(ARM_REG_ENDING);
	_id2regs.resize(ARM_REG_ENDING, nullptr);
	_regStackPointerId = ARM_REG_SP;
}

AbiArm::~AbiArm()
{

}

bool AbiArm::isNopInstruction(cs_insn* insn)
{
	// True NOP variants.
	//
	if (insn->id == ARM_INS_NOP)
	{
		return true;
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
