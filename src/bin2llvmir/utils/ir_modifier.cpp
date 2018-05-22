/**
 * @file src/bin2llvmir/utils/ir_modifier.cpp
 * @brief Modify both LLVM IR and config.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/InstIterator.h>

#include "retdec/bin2llvmir/utils/utils.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/bin2llvmir/utils/instruction.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

IrModifier::IrModifier(llvm::Module* m, Config* c) :
		_module(m),
		_config(c)
{

}

IrModifier::FunctionPair IrModifier::renameFunction(
		llvm::Function* fnc,
		const std::string& fncName)
{
	auto* cf = _config->getConfigFunction(fnc);
	auto n = retdec::utils::normalizeNamePrefix(fncName);
	if (n == fnc->getName())
	{
		return {fnc, cf};
	}

	fnc->setName(n);
	if (cf)
	{
		cf = _config->renameFunction(cf, fnc->getName());
	}
	else
	{
		cf = _config->insertFunction(fnc);
	}
	return {fnc, cf};
}

/**
 * Get or create&get stack variable.
 * @param fnc    Function owning the stack variable.
 * @param offset Stack varibale's offset.
 * @param type   Stack varibale's type.
 * @param name   Stack varibale's name in IR. If not set default name is used.
 *               Offset is always appended to this name. If you want to get
 *               this name to output C, set it as a real name to returned
 *               config stack variable entry.
 * @return Pair of LLVM stack var (Alloca instruction) and associated config
 *         stack var.
 */
IrModifier::StackPair IrModifier::getStackVariable(
		llvm::Function* fnc,
		int offset,
		llvm::Type* type,
		const std::string& name)
{
	if (!PointerType::isValidElementType(type))
	{
		type = getDefaultType(fnc->getParent());
	}

	std::string n = name.empty() ? "stack_var" : name;
	n += "_" + std::to_string(offset);
	AllocaInst* ret = _config->getLlvmStackVariable(fnc, offset);
	if (ret)
	{
		auto* csv = _config->getConfigStackVariable(ret);
		assert(csv);
		return {ret, csv};
	}

	ret = new AllocaInst(type, n);

	auto it = inst_begin(fnc);
	assert(it != inst_end(fnc)); // -> create bb, insert alloca.
	ret->insertBefore(&*it);

	auto* csv = _config->insertStackVariable(ret, offset);

	return {ret, csv};
}

bool IrModifier::localize(
		llvm::StoreInst* definition,
		std::set<llvm::Instruction*>& uses)
{
	auto* ptr = definition->getPointerOperand();
	auto* f = definition->getFunction();

	auto* local = new AllocaInst(ptr->getType()->getPointerElementType());
	local->insertBefore(&f->getEntryBlock().front());

	new StoreInst(definition->getValueOperand(), local, definition);
	definition->eraseFromParent();

	for (auto* u : uses)
	{
		u->replaceUsesOfWith(ptr, local);
	}

	return true;
}

} // namespace bin2llvmir
} // namespace retdec
