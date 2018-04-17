/**
 * @file include/retdec/bin2llvmir/analyses/symbolic_tree.h
 * @brief Construction of symbolic tree from the given node.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 *
 * This is an implementation of symbolic interpret. It is provided with
 * an initial node (llvm::Value) and it builds symbolic tree representing
 * the value of the node.
 */

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_SYMBOLIC_TREE_H
#define RETDEC_BIN2LLVMIR_ANALYSES_SYMBOLIC_TREE_H

#include <set>
#include <unordered_set>
#include <vector>

#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class SymbolicTree
{
	public:
		SymbolicTree(
				ReachingDefinitionsAnalysis& rda,
				llvm::Value* v,
				unsigned maxNodeLevel = 16);
		SymbolicTree(
				ReachingDefinitionsAnalysis& rda,
				llvm::Value* v,
				std::map<llvm::Value*, llvm::Value*>* val2val,
				unsigned maxNodeLevel = 16);

		SymbolicTree(const SymbolicTree& other) = default;
		SymbolicTree(SymbolicTree&& other) = default;
		SymbolicTree& operator=(SymbolicTree&& other);
		bool operator==(const SymbolicTree& o) const;
		bool operator!=(const SymbolicTree& o) const;
		friend std::ostream& operator<<(
				std::ostream& out,
				const SymbolicTree& s);
		std::string print(unsigned indent = 0) const;

		unsigned getLevel() const;

		bool isConstructedSuccessfully() const;
		bool isVal2ValMapUsed() const;
		void removeRegisterValues(Config* config);
		void removeGeneralRegisterLoads(Config* config);
		void removeStackLoads(Config* config);

		void simplifyNode(Config* config);

		void solveMemoryLoads(FileImage* image);
		SymbolicTree* getMaxIntValue();

		std::vector<SymbolicTree*> getPreOrder() const;
		std::vector<SymbolicTree*> getPostOrder() const;
		std::vector<SymbolicTree*> getLevelOrder() const;

	// This is a private constructor, do not use it. It is made public only
	// so it can be used in std::vector<>::emplace_back().
	//
	public:
		SymbolicTree(
				ReachingDefinitionsAnalysis* rda,
				llvm::Value* v,
				llvm::Value* u,
				std::unordered_set<llvm::Value*>& processed,
				unsigned nodeLevel,
				unsigned maxNodeLevel,
				std::map<llvm::Value*, llvm::Value*>* v2v = nullptr);
	private:

		void expandNode(
				ReachingDefinitionsAnalysis* RDA,
				std::map<llvm::Value*, llvm::Value*>* val2val,
				unsigned maxNodeLevel,
				std::unordered_set<llvm::Value*>& processed);
		void propagateFlags();

		void _simplifyNode(Config* config);
		void simplifyNodeLoadStore();
		void fixLevel(unsigned level = 0);

		void _getPreOrder(std::vector<SymbolicTree*>& res) const;
		void _getPostOrder(std::vector<SymbolicTree*>& res) const;

	public:
		llvm::Value* value = nullptr;
		llvm::Value* user = nullptr;
		std::vector<SymbolicTree> ops;

	private:
		bool _failed = false;
		bool _val2valUsed = false;
		unsigned _level = 1;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
