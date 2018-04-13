/**
* @file include/retdec/bin2llvmir/utils/capstone.h
* @brief Capstone utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_UTILS_CAPSTONE_H
#define RETDEC_BIN2LLVMIR_UTILS_CAPSTONE_H

#include <capstone/capstone.h>

#include "retdec/config/config.h"

namespace retdec {
namespace bin2llvmir {
namespace capstone_utils {

bool isNopInstruction(const config::Architecture& arch, cs_insn* insn);
bool isNopInstruction_x86(cs_insn* insn);
bool isNopInstruction_mips(cs_insn* insn);
bool isNopInstruction_arm(cs_insn* insn);

} // namespace capstone_utils
} // namespace bin2llvmir
} // namespace retdec

#endif
