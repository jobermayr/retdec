/**
 * @file src/bin2llvmir/providers/abi/mips.h
 * @brief ABI information for MIPS.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/mips.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

AbiMips::AbiMips(llvm::Module* m, Config* c) :
		Abi(m, c)
{
	_regs.resize(MIPS_REG_ENDING, nullptr);
	_regStackPointerId = MIPS_REG_SP;
}

AbiMips::~AbiMips()
{

}

bool AbiMips::isNopInstruction(AsmInstruction ai)
{
	cs_insn* insn = ai.getCapstoneInsn();
	cs_mips& insnMips = insn->detail->mips;

	// True NOP variants.
	//
	if (insn->id == MIPS_INS_NOP
			|| insn->id == MIPS_INS_SSNOP)
	{
		return true;
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
