/**
* @file src/bin2llvmir/optimizations/decoder/decoder.cpp
* @brief Decoding methods specific to x86 architecture.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/utils/string.h"

using namespace retdec::llvm_support;
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
				&& isNopInstruction(_dryCsInsn))
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

	if (getBasicBlockAtAddress(addr))
	{
		return false;
	}

	return true;
}

} // namespace bin2llvmir
} // namespace retdec
