/**
* @file include/retdec/bin2llvmir/optimizations/decoder/pseudo_call_worklist.h
* @brief Worklist of pseudo calls that need to be solved.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_PSEUDO_CALL_WORKLIST_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_PSEUDO_CALL_WORKLIST_H

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

namespace retdec {
namespace bin2llvmir {

class PseudoCall
{
	public:
		enum class eType
		{
			CALL,
			BR,
			COND_BR,
			RETURN,
		};

	public:
		PseudoCall(eType t, llvm::CallInst* c);

	public:
		eType type;
		llvm::CallInst* pseudoCall = nullptr;

		llvm::Function* targetFunction = nullptr;
		llvm::BasicBlock* targetBbTrue = nullptr;
		llvm::BasicBlock* targetBbFalse = nullptr;
};

class PseudoCallWorklist
{
	public:
		void addPseudoCall(llvm::CallInst* c);
		void addPseudoBr(llvm::CallInst* c);
		void addPseudoCondBr(llvm::CallInst* c);
		void addPseudoReturn(llvm::CallInst* c);

		void setTargetFunction(llvm::CallInst* c, llvm::Function* f);
		void setTargetBbTrue(llvm::CallInst* c, llvm::BasicBlock* b);
		void setTargetBbFalse(llvm::CallInst* c, llvm::BasicBlock* b);

	private:
		std::map<llvm::CallInst*, PseudoCall> _worklist;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
