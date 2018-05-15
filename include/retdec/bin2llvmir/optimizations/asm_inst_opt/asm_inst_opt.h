/**
 * @file include/retdec/bin2llvmir/optimizations/asm_inst_opt/asm_inst_opt.h
 * @brief Optimize a single assembly instruction.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_OPT_ASM_INST_OPTIMIZER_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_OPT_ASM_INST_OPTIMIZER_H

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"

#include "retdec/bin2llvmir/optimizations/asm_inst_opt/x86.h"

namespace retdec {
namespace bin2llvmir {
namespace asm_inst_opt {

namespace do_not_use_directly {

inline bool optimize_dummy(Abi*, retdec::bin2llvmir::AsmInstruction)
{
	return false;
}

} // namespace do_not_use_directly

/**
 * Optimize assembly instruction \p ai using optimization for architecture
 * \p arch. Abi \p abi might be needed in the process.
 *
 * This checks architecture every time to learn which optimization to use.
 * If you plan to use it on multiple assembly instructions, take a look at
 * \c getOptimizationFunction().
 */
bool optimize(config::Architecture& arch, Abi* a, AsmInstruction ai);

/**
 * Get an assembly instruction optimization function for the given architecture
 * \p arch.
 * This can be used to optimize multiple assembly instructions without
 * checking architecture each time.
 *
 * Example of use:
 * \code{.cpp}
 *   auto opt = getOptimizationFunction(arch);
 *   opt(asm);
 * \endcode
 */
inline auto getOptimizationFunction(config::Architecture& arch)
{
	if (arch.isX86_32())
	{
		return optimize_x86_32;
	}
	else
	{
		// ...
	}

	return do_not_use_directly::optimize_dummy;
}

} // namespace asm_inst_opt
} // namespace bin2llvmir
} // namespace retdec

#endif
