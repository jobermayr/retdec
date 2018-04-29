/**
 * @file src/bin2llvmir/optimizations/asm_inst_optimizer/asm_inst_optimizer.cpp
 * @brief Optimize a single assembly instruction.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/optimizations/asm_inst_opt/asm_inst_opt.h"
#include "retdec/bin2llvmir/optimizations/asm_inst_opt/x86.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace asm_inst_opt {

bool optimize(AsmInstruction ai, config::Architecture& arch)
{
	if (arch.isX86())
	{
		return optimize_x86(ai);
	}
	else
	{
		// ...
	}

	return false;
}

} // namespace asm_inst_opt
} // namespace bin2llvmir
} // namespace retdec
