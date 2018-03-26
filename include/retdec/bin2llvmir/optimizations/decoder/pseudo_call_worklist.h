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

#include "retdec/utils/address.h"

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
			SWITCH,
		};

	public:
		PseudoCall(eType t, llvm::CallInst* c);

	public:
		eType type;
		llvm::CallInst* pseudoCall = nullptr;

		llvm::Function* targetFunction = nullptr;
		llvm::BasicBlock* targetBbTrue = nullptr;
		llvm::BasicBlock* targetBbFalse = nullptr;

		// Switch.
		llvm::Value* switchValue = nullptr;
		utils::Address defaultCase;
		llvm::BasicBlock* defaultCaseBb = nullptr;
		std::vector<std::pair<utils::Address, llvm::BasicBlock*>> cases;
		std::set<utils::Address> missingCases;
};

class PseudoCallWorklist
{
	public:
		void addPseudoCall(llvm::CallInst* c);
		void addPseudoBr(llvm::CallInst* c);
		void addPseudoCondBr(llvm::CallInst* c);
		void addPseudoSwitch(
				llvm::CallInst* c,
				llvm::Value* switchValue,
				const std::vector<utils::Address>& cases,
				utils::Address defaultCase = utils::Address::getUndef);

		void setTargetFunction(llvm::CallInst* c, llvm::Function* f);
		void setTargetBbTrue(llvm::CallInst* c, llvm::BasicBlock* b);
		void setTargetBbTrue(llvm::CallInst* c, llvm::Function* f);
		void setTargetBbFalse(llvm::CallInst* c, llvm::BasicBlock* b);
		void setTargetBbSwitchCase(
				llvm::CallInst* c,
				utils::Address a,
				llvm::BasicBlock* b);

	public:
		std::map<llvm::CallInst*, PseudoCall> _worklist;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
