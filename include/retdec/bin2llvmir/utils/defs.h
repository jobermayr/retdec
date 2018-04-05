/**
* @file include/retdec/bin2llvmir/utils/defs.h
* @brief Aliases for several useful types with LLVM IR items.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_UTILS_DEFS_H
#define RETDEC_BIN2LLVMIR_UTILS_DEFS_H

#include <iostream>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/Instruction.h>

namespace retdec {
namespace bin2llvmir {

/// Set of global variables.
using GlobVarSet = std::set<llvm::GlobalVariable*>;

/// Vector of call-graph nodes.
using CallGraphNodeVec = std::vector<llvm::CallGraphNode*>;

/// Vector of basic blocks.
using BBVec = std::vector<llvm::BasicBlock*>;

/// Set of basic blocks.
using BBSet = std::set<llvm::BasicBlock*>;

/// Vector of instructions.
using InstVec = std::vector<llvm::Instruction*>;

/// Set of instructions.
using InstSet = std::set<llvm::Instruction*>;

/// Unordered set of instructions.
using UnorderedInstSet = std::unordered_set<llvm::Instruction*>;

/// Set of values.
using ValSet = std::set<llvm::Value*>;

/// Unordered set of values.
using UnorderedValSet = std::unordered_set<llvm::Value*>;

/// Vector of functions.
using FuncVec = std::vector<llvm::Function*>;

/// Set of functions.
using FuncSet = std::set<llvm::Function*>;

/// Set of @c CallInst.
using CallInstSet = std::set<llvm::CallInst*>;

/// Mapping of an instruction to a set of instructions.
using InstInstSetMap = std::map<llvm::Instruction*, InstSet>;

/// Mapping of a string to vector of functions.
using StringVecFuncMap = std::map<std::string, FuncVec>;

/// Unordered set of values.
using UnorderedTypeSet = std::unordered_set<llvm::Type*>;

#define LOG \
	if (!debug_enabled) {} \
	else std::cout << std::showbase

} // namespace bin2llvmir
} // namespace retdec

#endif
