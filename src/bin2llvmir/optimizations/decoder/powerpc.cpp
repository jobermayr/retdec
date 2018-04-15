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

std::size_t Decoder::decodeJumpTargetDryRun_ppc(
		const JumpTarget& jt,
		ByteData bytes)
{
	return false;
}

} // namespace bin2llvmir
} // namespace retdec
