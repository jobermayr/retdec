/**
 * @file include/retdec/bin2llvmir/optimizations/asm_inst_optimizer/asm_inst_optimizer.h
 * @brief Optimize a single assembly instruction.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef INCLUDE_RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_OPTIMIZER_ASM_INST_OPTIMIZER_H_
#define INCLUDE_RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_OPTIMIZER_ASM_INST_OPTIMIZER_H_

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
