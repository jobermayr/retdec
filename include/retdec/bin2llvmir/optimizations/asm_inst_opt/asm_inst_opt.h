/**
 * @file include/retdec/bin2llvmir/optimizations/asm_inst_opt/asm_inst_opt.h
 * @brief Optimize a single assembly instruction.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_OPT_ASM_INST_OPTIMIZER_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_OPT_ASM_INST_OPTIMIZER_H

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"

namespace retdec {
namespace bin2llvmir {
namespace asm_inst_opt {

bool optimize(AsmInstruction ai, config::Architecture& arch);

} // namespace asm_inst_opt
} // namespace bin2llvmir
} // namespace retdec

#endif
