/**
* @file src/bin2llvmir/optimizations/decoder/x86.cpp
* @brief Decoding methods specific to x86 architecture.
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

std::size_t Decoder::decodeJumpTargetDryRun_x86(
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

		if (_c2l->isReturnInstruction(*_dryCsInsn)
				|| _c2l->isBranchInstruction(*_dryCsInsn))
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

void Decoder::eraseReturnAddrStoreInCall_x86(llvm::CallInst* c)
{
	Instruction* it = c;
	while (it && !AsmInstruction::isLlvmToAsmInstruction(it))
	{
		auto* i = it;
		it = it->getPrevNode();
		if (auto* st = dyn_cast<StoreInst>(i))
		{
			if (_config->isStackPointerRegister(st->getPointerOperand())
					|| isa<ConstantInt>(st->getValueOperand()))
			{
				st->eraseFromParent();
			}
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
