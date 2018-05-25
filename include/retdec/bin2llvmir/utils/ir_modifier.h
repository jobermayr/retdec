/**
 * @file include/retdec/bin2llvmir/utils/ir_modifier.h
 * @brief Modify both LLVM IR and config.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_IR_MODIFIER_H
#define RETDEC_BIN2LLVMIR_UTILS_IR_MODIFIER_H

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class IrModifier
{
	public:
		using FunctionPair = std::pair<llvm::Function*, retdec::config::Function*>;
		using StackPair = std::pair<llvm::AllocaInst*, retdec::config::Object*>;

	// Methods not using member data -> do not need instance of this class.
	// Can be used simply like this: \c IrModifier::method().
	//
	public:
		static bool localize(
				llvm::StoreInst* definition,
				std::set<llvm::Instruction*>& uses);

		static llvm::AllocaInst* createAlloca(
				llvm::Function* fnc,
				llvm::Type* ty,
				const std::string& name = "");

		static llvm::Value* convertValueToType(
				llvm::Value* val,
				llvm::Type* type,
				llvm::Instruction* before);

		static llvm::Value* convertValueToTypeAfter(
				llvm::Value* val,
				llvm::Type* type,
				llvm::Instruction* after);

		static llvm::Constant* convertConstantToType(
				llvm::Constant* val,
				llvm::Type* type);

	public:
		IrModifier(llvm::Module* m, Config* c);

	// Methods using member data -> need instance of this class.
	//
	public:
		FunctionPair renameFunction(
				llvm::Function* fnc,
				const std::string& fncName);

		StackPair getStackVariable(
				llvm::Function* fnc,
				int offset,
				llvm::Type* type,
				const std::string& name = "stack_var");

	protected:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
