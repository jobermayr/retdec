/**
* @file include/retdec/bin2llvmir/optimizations/stack_protect/stack_protect.h
* @brief Protect stack variables from LLVM optimization passes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_STACK_PROTECT_STACK_PROTECT_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_STACK_PROTECT_STACK_PROTECT_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class StackProtect : public llvm::ModulePass
{
	public:
		static char ID;
		StackProtect();
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnModuleCustom(llvm::Module& M, Config* c);

	private:
		bool run();
		void protect();
		void protectStack();
		void protectRegisters();
		void unprotect();

		void protectValue(
				llvm::Value* val,
				llvm::Type* t,
				llvm::Instruction* before);

		llvm::Function* getOrCreateFunction(llvm::Type* t);
		llvm::Function* createFunction(llvm::Type* t);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		static std::map<llvm::Type*, llvm::Function*> _type2fnc;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
