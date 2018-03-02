/**
* @file include/retdec/bin2llvmir/optimizations/decoder/decoder.h
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_DECODER_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_DECODER_H

#include <map>
#include <queue>
#include <sstream>

#include <llvm/IR/CFG.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/utils/address.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/optimizations/decoder/jump_targets.h"
#include "retdec/bin2llvmir/optimizations/decoder/pseudo_call_worklist.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/capstone2llvmir/capstone2llvmir.h"

// Debug logs enabled/disabled.
#include "retdec/bin2llvmir/utils/defs.h"
#define debug_enabled true

namespace retdec {
namespace bin2llvmir {

class Decoder : public llvm::ModulePass
{
	public:
		static char ID;
		Decoder();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				FileImage* o,
				DebugFormat* d);

	private:
		bool runCatcher();
		bool run();

		void initTranslator();
		void initEnvironment();
		void initEnvironmentAsm2LlvmMapping();
		void initEnvironmentPseudoFunctions();
		void initEnvironmentRegisters();
		void initRanges();
		void initAllowedRangesWithSegments();
		void initJumpTargets();
		void initJumpTargetsEntryPoint();

		void decode();
		void decodeJumpTarget(const JumpTarget& jt);
		std::size_t decodeJumpTargetDryRun(
				const JumpTarget& jt,
				std::pair<const std::uint8_t*, std::uint64_t> bytes);
		std::size_t decodeJumpTargetDryRun_x86(const JumpTarget& jt,
				std::pair<const std::uint8_t*, std::uint64_t> bytes);

		bool getJumpTargetsFromInstruction(
				AsmInstruction& ai,
				capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr);
		void analyzeInstruction(
				AsmInstruction& ai,
				capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr);
		llvm::IRBuilder<> getIrBuilder(const JumpTarget& jt);
		retdec::utils::Address getJumpTarget(llvm::Value* val);

		retdec::utils::Address getFunctionAddress(llvm::Function* f);
		retdec::utils::Address getFunctionEndAddress(llvm::Function* f);
		llvm::Function* getFunctionAtAddress(retdec::utils::Address a);
		llvm::Function* getFunctionBeforeAddress(retdec::utils::Address a);
		llvm::Function* getFunctionContainingAddress(retdec::utils::Address a);
		llvm::Function* createFunction(
				retdec::utils::Address a,
				const std::string& name);

		retdec::utils::Address getBasicBlockAddress(llvm::BasicBlock* b);
		retdec::utils::Address getBasicBlockEndAddress(llvm::BasicBlock* b);
		llvm::BasicBlock* getBasicBlockAtAddress(retdec::utils::Address a);
		llvm::BasicBlock* getBasicBlockBeforeAddress(retdec::utils::Address a);
		llvm::BasicBlock* getBasicBlockContainingAddress(retdec::utils::Address a);
		llvm::BasicBlock* createBasicBlock(
				retdec::utils::Address a,
				const std::string& name,
				llvm::Function* f,
				llvm::BasicBlock* insertAfter = nullptr);

		void dumpControFlowToJson_jsoncpp();
		void dumpControFlowToJsonModule_manual();
		void dumpControFlowToJsonFunction_manual(
				llvm::Function& f,
				std::ostream &out);
		void dumpControFlowToJsonBasicBlock_manual(
				llvm::BasicBlock& bb,
				std::ostream &out);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _image = nullptr;
		DebugFormat* _debug = nullptr;

		cs_mode _currentMode = CS_MODE_LITTLE_ENDIAN;
		std::unique_ptr<capstone2llvmir::Capstone2LlvmIrTranslator> _c2l;

		retdec::utils::AddressRangeContainer _allowedRanges;
		retdec::utils::AddressRangeContainer _alternativeRanges;
		retdec::utils::AddressRangeContainer _processedRanges;

		JumpTargets _jumpTargets;
		PseudoCallWorklist _pseudoWorklist;

		std::map<retdec::utils::Address, llvm::Function*> _addr2fnc;
		std::map<llvm::Function*, retdec::utils::Address> _fnc2addr;
		std::map<retdec::utils::Address, llvm::BasicBlock*> _addr2bb;
		std::map<llvm::BasicBlock*, retdec::utils::Address> _bb2addr;

		std::map<llvm::StoreInst*, cs_insn*>* _llvm2capstone = nullptr;

	private:
		const std::string _asm2llvmGv = "_asm_program_counter";
		const std::string _asm2llvmMd = "llvmToAsmGlobalVariableName";
		const std::string _callFunction = "__pseudo_call";
		const std::string _returnFunction = "__pseudo_return";
		const std::string _branchFunction = "__pseudo_branch";
		const std::string _condBranchFunction = "__pseudo_cond_branch";
		const std::string _x87dataLoadFunction = "__frontend_reg_load.fpr";
		const std::string _x87tagLoadFunction = "__frontend_reg_load.fpu_tag";
		const std::string _x87dataStoreFunction = "__frontend_reg_store.fpr";
		const std::string _x87tagStoreFunction = "__frontend_reg_store.fpu_tag";
		const std::string _entryPointFunction = "entry_point";
};

} // namespace bin2llvmir
} // namespace retdec

#endif
