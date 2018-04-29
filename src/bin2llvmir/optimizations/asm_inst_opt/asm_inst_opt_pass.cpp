/**
 * @file include/retdec/bin2llvmir/optimizations/asm_inst_optimizer/asm_inst_optimizer_pass.h
 * @brief Optimize assembly instructions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/optimizations/asm_inst_opt/asm_inst_opt_pass.h"
#include "retdec/bin2llvmir/optimizations/asm_inst_opt/asm_inst_opt.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char AsmInstructionOptimizer::ID = 0;

static RegisterPass<AsmInstructionOptimizer> X(
		"asm-inst-opt",
		"Optimize a single assembly instruction.",
		false, // Only looks at CFG
		false // Analysis Pass
);


AsmInstructionOptimizer::AsmInstructionOptimizer() :
		ModulePass(ID)
{

}

bool AsmInstructionOptimizer::runOnModule(Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	return run();
}

bool AsmInstructionOptimizer::runOnModuleCustom(
		llvm::Module& m,
		Config* c)
{
	_module = &m;
	_config = c;
	return run();
}

bool AsmInstructionOptimizer::run()
{
	bool changed = false;

	for (auto& f : *_module)
	{
		for (auto ai = AsmInstruction(&f); ai.isValid(); ai = ai.getNext())
		{
			changed |= asm_inst_opt::optimize(
					ai,
					_config->getConfig().architecture);
		}
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec
