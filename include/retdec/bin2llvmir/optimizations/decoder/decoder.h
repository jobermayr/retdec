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
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/bin2llvmir/optimizations/decoder/jump_targets.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/capstone2llvmir/capstone2llvmir.h"
#include "retdec/stacofin/stacofin.h"

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
		~Decoder();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				FileImage* o,
				DebugFormat* d,
				NameContainer* n);

	private:
		using ByteData = typename std::pair<const std::uint8_t*, std::uint64_t>;

	private:
		bool runCatcher();
		bool run();

		void initTranslator();
		void initDryRunCsInstruction();
		void initEnvironment();
		void initEnvironmentAsm2LlvmMapping();
		void initEnvironmentPseudoFunctions();
		void initEnvironmentRegisters();
		void initRanges();
		void initAllowedRangesWithSegments();
		void initJumpTargets();
		void initJumpTargetsConfig();
		void initJumpTargetsEntryPoint();
		void initJumpTargetsImports();
		void initJumpTargetsExports();
		void initJumpTargetsDebug();
		void initJumpTargetsSymbols();
		void initConfigFunction();

		void initStaticCode();
		void addStaticFunction(
				retdec::utils::Address addr,
				stacofin::DetectedFunction& df,
				std::map<retdec::utils::Address, std::pair<retdec::utils::Address, std::string>>& solvedRefs);

		void decode();
		bool getJumpTarget(JumpTarget& jt);
		void decodeJumpTarget(const JumpTarget& jt);
		std::size_t decodeJumpTargetDryRun(
				const JumpTarget& jt,
				ByteData bytes);

		bool getJumpTargetsFromInstruction(
				retdec::utils::Address addr,
				capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr);
		retdec::utils::Address getJumpTarget(
				retdec::utils::Address addr,
				llvm::CallInst* branchCall,
				llvm::Value* val);

		retdec::utils::Address getFunctionAddress(llvm::Function* f);
		retdec::utils::Address getFunctionEndAddress(llvm::Function* f);
		retdec::utils::Address getFunctionAddressAfter(retdec::utils::Address a);
		llvm::Function* getFunctionAtAddress(retdec::utils::Address a);
		llvm::Function* getFunctionBeforeAddress(retdec::utils::Address a);
		llvm::Function* getFunctionAfterAddress(retdec::utils::Address a);
		llvm::Function* getFunctionContainingAddress(retdec::utils::Address a);
		llvm::Function* createFunction(
				retdec::utils::Address a,
				bool declaration = false);

		retdec::utils::Address getBasicBlockAddress(llvm::BasicBlock* b);
		retdec::utils::Address getBasicBlockEndAddress(llvm::BasicBlock* b);
		retdec::utils::Address getBasicBlockAddressAfter(retdec::utils::Address a);
		llvm::BasicBlock* getBasicBlockAtAddress(retdec::utils::Address a);
		llvm::BasicBlock* getBasicBlockBeforeAddress(retdec::utils::Address a);
		llvm::BasicBlock* getBasicBlockAfterAddress(retdec::utils::Address a);
		llvm::BasicBlock* getBasicBlockContainingAddress(retdec::utils::Address a);
		llvm::BasicBlock* createBasicBlock(
				retdec::utils::Address a,
				const std::string& name,
				llvm::Function* f,
				llvm::BasicBlock* insertAfter = nullptr);

		void dumpControFlowToJsonModule_manual();
		void dumpControFlowToJsonFunction_manual(
				llvm::Function& f,
				std::ostream &out);
		void dumpControFlowToJsonBasicBlock_manual(
				llvm::BasicBlock& bb,
				llvm::BasicBlock& bbEnd,
				std::ostream &out);

		bool isNopInstruction(cs_insn* insn);

		void splitOnTerminatingCalls();

		llvm::Function* _splitFunctionOn(
				retdec::utils::Address addr,
				const std::string& fncName = "");
		llvm::Function* _splitFunctionOn(
				retdec::utils::Address addr,
				llvm::BasicBlock* bb,
				const std::string& fncName = "");

		void getOrCreateTarget(
				retdec::utils::Address addr,
				bool isCall,
				llvm::BasicBlock*& tBb,
				llvm::Function*& tFnc,
				llvm::Instruction* fromI = nullptr);

		void removePseudoCalls();

		llvm::CallInst* transformToCall(
				llvm::CallInst* pseudo,
				llvm::Function* callee);
		llvm::CallInst* transformToCondCall(
				llvm::CallInst* pseudo,
				llvm::Value* cond,
				llvm::Function* callee,
				llvm::BasicBlock* falseBb);
		llvm::ReturnInst* transformToReturn(llvm::CallInst* pseudo);
		llvm::BranchInst* transformToBranch(
				llvm::CallInst* pseudo,
				llvm::BasicBlock* branchee);
		llvm::BranchInst* transformToCondBranch(
				llvm::CallInst* pseudo,
				llvm::Value* cond,
				llvm::BasicBlock* trueBb,
				llvm::BasicBlock* falseBb);
		llvm::SwitchInst* transformToSwitch(
				llvm::CallInst* pseudo,
				llvm::Value* val,
				llvm::BasicBlock* defaultBb,
				const std::vector<llvm::BasicBlock*>& cases);

		void removeRange(const retdec::utils::AddressRange& ar);
		void removeRange(retdec::utils::Address s, retdec::utils::Address e);

	// x86 specifix.
	//
	private:
		std::size_t decodeJumpTargetDryRun_x86(
				const JumpTarget& jt,
				ByteData bytes);
		bool isNopInstruction_x86(cs_insn* insn);
		void eraseReturnAddrStoreInCall_x86(llvm::CallInst* c);

	// ARM specific.
	//
	private:
		std::size_t decodeJumpTargetDryRun_arm(
				const JumpTarget& jt,
				ByteData bytes);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _image = nullptr;
		DebugFormat* _debug = nullptr;
		NameContainer* _names = nullptr;
		Llvm2CapstoneMap* _llvm2capstone = nullptr;

		cs_mode _currentMode = CS_MODE_LITTLE_ENDIAN;
		std::unique_ptr<capstone2llvmir::Capstone2LlvmIrTranslator> _c2l;

		retdec::utils::AddressRangeContainer _allowedRanges;
		retdec::utils::AddressRangeContainer _alternativeRanges;
		retdec::utils::AddressRangeContainer _originalAllowedRanges;

		JumpTargets _jumpTargets;

		std::map<retdec::utils::Address, llvm::Function*> _addr2fnc;
		std::map<llvm::Function*, retdec::utils::Address> _fnc2addr;
		std::map<retdec::utils::Address, llvm::BasicBlock*> _addr2bb;
		std::map<llvm::BasicBlock*, retdec::utils::Address> _bb2addr;

		std::map<retdec::utils::Address, std::string> _imports;
		std::set<retdec::utils::Address> _exports;
		std::set<retdec::utils::Address> _debugFncs;
		std::set<retdec::utils::Address> _staticFncs;
		std::set<llvm::Function*> _terminatingFncs;

		cs_insn* _dryCsInsn = nullptr;

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
};

} // namespace bin2llvmir
} // namespace retdec

#endif
