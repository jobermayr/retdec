/**
 * @file include/retdec/bin2llvmir/optimizations/asm_inst_opt/asm_inst_opt_pass.h
 * @brief Optimize assembly instructions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_OPT_ASM_INST_OPT_PASS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ASM_INST_OPT_ASM_INST_OPT_PASS_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class AsmInstructionOptimizer : public llvm::ModulePass
{
	public:
		static char ID;
		AsmInstructionOptimizer();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(llvm::Module& m, Config* c);

	private:
		bool run();

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
