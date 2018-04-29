/**
 * @file include/retdec/bin2llvmir/optimizations/asm_inst_opt/x86.h
 * @brief Optimize a single x86 assembly instruction.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_OPT_X86_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_OPT_X86_H

#include "retdec/bin2llvmir/providers/asm_instruction.h"

namespace retdec {
namespace bin2llvmir {
namespace asm_inst_opt {

bool optimize_x86(AsmInstruction ai);

} // namespace asm_inst_opt
} // namespace bin2llvmir
} // namespace retdec


#endif
