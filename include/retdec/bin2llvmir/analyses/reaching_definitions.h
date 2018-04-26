/**
* @file include/retdec/bin2llvmir/analyses/reaching_definitions.h
* @brief Reaching definitions analysis (RDA) builds UD and DU chains.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* Right now, this works on an entire module. But we could insert an another layer
* that represents functions. Then it would be possible to associate BBs with
* functions that own them and recompute RDA only for the selected function.
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_REACHING_DEFINITIONS_H
#define RETDEC_BIN2LLVMIR_ANALYSES_REACHING_DEFINITIONS_H

#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/utils/debug.h"

namespace retdec {
namespace bin2llvmir {

class Definition;
class Use;
class BasicBlockEntry;
class ReachingDefinitionsAnalysis;

using Changed = bool;

using BBEntrySet = std::unordered_set<BasicBlockEntry*>;

using DefSet = std::unordered_set<Definition*>;
using UseSet = std::unordered_set<Use*>;

using DefVector = std::vector<Definition>;
using UseVector = std::vector<Use>;

class Definition
{
	public:
		Definition(llvm::Instruction* d, llvm::Value* s);
		bool operator==(const Definition& o) const;

		llvm::Value* getSource();

	public:
		llvm::Instruction* def;
		llvm::Value* src;
		UseSet uses;
};

class Use
{
	public:
		Use(llvm::Instruction* u, llvm::Value* s);
		bool operator==(const Use &o) const;

		bool isUndef() const;

	public:
		llvm::Instruction* use;
		llvm::Value* src;
		DefSet defs;
};

class BasicBlockEntry
{
	public:
		BasicBlockEntry(const llvm::BasicBlock* b = nullptr);

		std::string getName() const;
		friend std::ostream& operator<<(
				std::ostream& out,
				const BasicBlockEntry& bbe);

		void initializeKillDefSets();
		Changed initDefsOut();

		const DefSet& defsFromUse(const llvm::Instruction* I) const;
		const UseSet& usesFromDef(const llvm::Instruction* I) const;
		const Definition* getDef(const llvm::Instruction* I) const;
		const Use* getUse(const llvm::Instruction* I) const;

	public:
		const llvm::BasicBlock* bb;

		DefVector defs;
		UseVector uses;

		BBEntrySet prevBBs;

		// defsIn is union of prevBBs' defsOuts
		DefSet defsOut;
		DefSet genDefs;
		std::unordered_set<llvm::Value*> killDefs;

		bool changed = false;

	private:
		unsigned id;
	    static int newUID;
};

class ReachingDefinitionsAnalysis
{
	public:
		bool runOnModule(
				llvm::Module& M,
				Config* c = nullptr,
				bool trackFlagRegs = false);
		bool runOnFunction(
				llvm::Function& F,
				Config* c = nullptr,
				bool trackFlagRegs = false);
		void clear();
		bool wasRun() const;

	public:
		const DefSet& defsFromUse(const llvm::Instruction* I) const;
		const UseSet& usesFromDef(const llvm::Instruction* I) const;
		const Definition* getDef(const llvm::Instruction* I) const;
		const Use* getUse(const llvm::Instruction* I) const;

		friend std::ostream& operator<<(
				std::ostream& out,
				const ReachingDefinitionsAnalysis& rda);

	// TODO: experimental, light, on-demand methods that work without full RDA.
	// TODO: unit tests.
	// TODO: merge with defsFromUse()/usesFromDef() to common API.
	//
	public:
		std::set<llvm::Instruction*> defsFromUse_onDemand(
				llvm::Instruction* I) const;
		std::set<llvm::Instruction*> usesFromDef_onDemand(
				llvm::Instruction* I) const;
	private:
		llvm::Instruction* defInBasicBlock(
				llvm::Value* v,
				llvm::BasicBlock* bb,
				llvm::Instruction* start = nullptr) const;
		bool usesInBasicBlock(
				llvm::Value* v,
				llvm::BasicBlock* bb,
				std::set<llvm::Instruction*>& uses,
				llvm::Instruction* start = nullptr) const;

	private:
		void run();
		const BasicBlockEntry& getBasicBlockEntry(const llvm::Instruction* I) const;
		void initializeBasicBlocks(llvm::Module& M);
		void initializeBasicBlocks(llvm::Function& F);
		void initializeBasicBlocksPrev();
		void initializeKillGenSets();
		void propagate();
		void initializeDefsAndUses();
		void clearInternal();

	private:
		std::map<const llvm::Function*, std::map<const llvm::BasicBlock*, BasicBlockEntry>> bbMap;
		bool _trackFlagRegs = false;
		const llvm::GlobalVariable* _specialGlobal = nullptr;
		bool _run = false;

	public:
		Config* _config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
