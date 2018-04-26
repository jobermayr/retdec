/**
* @file include/retdec/bin2llvmir/optimizations/unreachable_funcs/unreachable_funcs.h
* @brief Removes unreachable functions from main.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_UNREACHABLE_FUNCS_UNREACHABLE_FUNCS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_UNREACHABLE_FUNCS_UNREACHABLE_FUNCS_H

#include <llvm/IR/InstVisitor.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/utils/debug.h"

namespace retdec {
namespace bin2llvmir {

/**
* @brief Removes unreachable functions from main.
*
* @code
* void func1() { ... } <- Not calls func2.
* void func2() { ... } <- Unreachable function. Can be optimized.
* int main() {
*   func1();
* }
* @endcode
*/
class UnreachableFuncs: public llvm::ModulePass {
public:
	static char ID;
	UnreachableFuncs();

	virtual bool runOnModule(llvm::Module &module) override;
	virtual void getAnalysisUsage(llvm::AnalysisUsage &au) const override;

	static const char *getName() { return NAME; }

private:
	void initializeMainFunc(llvm::Module &module);
	bool optimizationCanRun() const;
	std::set<llvm::Function*> getReachableFuncs(llvm::Function &startFunc,
		llvm::Module &module) const;
	void removeFuncsThatCanBeOptimized(
		const std::set<llvm::Function*> &funcsThatCannotBeOptimized,
		llvm::Module &module) const;
	std::set<llvm::Function*> getFuncsThatCannotBeOptimized(
		const std::set<llvm::Function*> &reachableFuncs, llvm::Module &module) const;
	std::set<llvm::Function*> getFuncsThatCanBeOptimized(
		const std::set<llvm::Function*> funcsThatCannotBeOptimized,
		llvm::Module &module) const;
	void removeFuncsFromModule(const std::set<llvm::Function*> &funcsToRemove) const;

private:
	/// Name of the optimization.
	static const char *NAME;

	/// The main function.
	llvm::Function *mainFunc;

	Config* config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
