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

//
//==============================================================================
// Local functions.
//==============================================================================
//

namespace {

Instruction* insertBeforeAfter(Instruction* i, Instruction* b, Instruction* a)
{
	if (b)
	{
		i->insertBefore(b);
	}
	else
	{
		i->insertAfter(a);
	}
	return i;
}

Value* convertToType(
		Value* val,
		Type* type,
		Instruction* before,
		Instruction* after,
		bool constExpr)
{
	if (val == nullptr
			|| type == nullptr
			|| (!constExpr && before == nullptr && after == nullptr))
	{
		return nullptr;
	}

	auto* cval = dyn_cast<Constant>(val);
	if (constExpr)
	{
		assert(cval);
	}

	auto& ctx = type->getContext();
	Value* conv = nullptr;

	if (val->getType() == type)
	{
		conv = val;
	}
	else if (val->getType()->isPointerTy() && type->isPointerTy())
	{
		if (constExpr)
		{
			conv = ConstantExpr::getBitCast(cval, type);
		}
		else
		{
			auto* i = new BitCastInst(val, type, "");
			conv = insertBeforeAfter(i, before, after);
		}
	}
	else if (val->getType()->isPointerTy() && type->isIntegerTy())
	{
		if (constExpr)
		{
			conv = ConstantExpr::getPtrToInt(cval, type);
		}
		else
		{
			auto* i = new PtrToIntInst(val, type, "");
			conv = insertBeforeAfter(i, before, after);
		}
	}
	else if (val->getType()->isIntegerTy() && type->isPointerTy())
	{
		if (constExpr)
		{
			conv = ConstantExpr::getIntToPtr(cval, type);
		}
		else
		{
			auto* i = new IntToPtrInst(val, type, "");
			conv = insertBeforeAfter(i, before, after);
		}
	}
	else if (val->getType()->isIntegerTy() && type->isIntegerTy())
	{
		if (constExpr)
		{
			conv = ConstantExpr::getIntegerCast(cval, type, true);
		}
		else
		{
			auto* i = CastInst::CreateIntegerCast(val, type, true, "");
			conv = insertBeforeAfter(i, before, after);
		}
	}
	else if (val->getType()->isIntegerTy() && type->isFloatingPointTy())
	{
		auto* toInt = Type::getIntNTy(ctx, type->getPrimitiveSizeInBits());
		auto* szConv = convertToType(val, toInt, before, after, constExpr);

		if (constExpr)
		{
			conv = ConstantExpr::getBitCast(cast<Constant>(szConv), type);
		}
		else
		{
			auto* i = new BitCastInst(szConv, type, "");
			auto* a = val == szConv ? after : cast<Instruction>(szConv);
			conv = insertBeforeAfter(i, before, a);
		}
	}
	else if (val->getType()->isPointerTy() && type->isFloatingPointTy())
	{
		auto* toInt = Type::getIntNTy(ctx, type->getPrimitiveSizeInBits());
		auto* intConv = convertToType(val, toInt, before, after, constExpr);
		auto* a = dyn_cast<Instruction>(intConv);
		conv = convertToType(intConv, type, before, a, constExpr);
	}
	else if (val->getType()->isFloatingPointTy() && type->isIntegerTy())
	{
		Type* ft = nullptr;
		IntegerType* intT = cast<IntegerType>(type);
		switch (intT->getBitWidth())
		{
			case 16: ft = Type::getHalfTy(ctx); break;
			case 32: ft = Type::getFloatTy(ctx); break;
			case 64: ft = Type::getDoubleTy(ctx); break;
			case 80: ft = Type::getX86_FP80Ty(ctx); break;
			default:
			{
				auto* fpConv = convertToType(
						val,
						Type::getInt32Ty(ctx),
						before,
						after,
						constExpr);
				auto* a = dyn_cast<Instruction>(fpConv);
				conv = convertToType(fpConv, intT, before, a, constExpr);
				return conv;
			}
		}

		if (val->getType() != ft)
		{
			auto* fpConv = convertToType(val, ft, before, after, constExpr);
			auto* a = dyn_cast<Instruction>(fpConv);
			conv = convertToType(fpConv, intT, before, a, constExpr);
		}
		else
		{
			if (constExpr)
			{
				conv = ConstantExpr::getBitCast(cval, intT);
			}
			else
			{
				auto* i = new BitCastInst(val, intT, "");
				conv = insertBeforeAfter(i, before, after);
			}
		}
	}
	else if (val->getType()->isFloatingPointTy() && type->isPointerTy())
	{
		auto* toInt = Type::getIntNTy(
				ctx,
				val->getType()->getPrimitiveSizeInBits());
		auto* intConv = convertToType(val, toInt, before, after, constExpr);
		auto* a = dyn_cast<Instruction>(intConv);
		conv = convertToType(intConv, type, before, a, constExpr);
	}
	else if (val->getType()->isFloatingPointTy() && type->isFloatingPointTy())
	{
		if (constExpr)
		{
			conv = ConstantExpr::getFPCast(cval, type);
		}
		else
		{
			auto* i = CastInst::CreateFPCast(val, type, "");
			conv = insertBeforeAfter(i, before, after);
		}
	}
	// TODO: this is too late, it would be the best if loads/stores that
	// load/store entire aggregate types were not created at all.
	// Such complex load/stores are not possible at ASM level.
	// Something like util function createSafe{Load,Store}() that would
	// check if loaded/stored value is not aggregate and if it is, it would
	// do the same this as here.
	//
	else if (isa<LoadInst>(val) && val->getType()->isAggregateType() && !constExpr)
	{
		auto* l = cast<LoadInst>(val);
		auto* c = cast<Instruction>(convertToType(
				l->getPointerOperand(),
				PointerType::get(type, 0),
				before,
				after,
				constExpr));
		auto* nl = new LoadInst(c);
		nl->insertAfter(c);
		conv = nl;
	}
	else if (val->getType()->isAggregateType())
	{
		std::vector<unsigned> idxs = { 0 };
		Value* toSimple = nullptr;
		if (constExpr)
		{
			toSimple = ConstantExpr::getExtractValue(
					cval,
					ArrayRef<unsigned>(idxs));
		}
		else
		{
			auto* i = ExtractValueInst::Create(
					val,
					ArrayRef<unsigned>(idxs),
					"");
			toSimple = insertBeforeAfter(i, before, after);
		}
		auto* a = dyn_cast<Instruction>(toSimple);
		conv = convertToType(toSimple, type, before, a, constExpr);
	}
	else if (CompositeType* cmp = dyn_cast<CompositeType>(type))
	{
		assert(!cmp->isEmptyTy());
		std::vector<unsigned> idxs = { 0 };
		auto* idxt = cmp->getTypeAtIndex(0u);
		auto* tmp = convertToType(val, idxt, before, after, constExpr);

		if (constExpr)
		{
			auto* c = dyn_cast<Constant>(tmp);
			assert(c);
			conv = ConstantExpr::getInsertValue(
					UndefValue::get(cmp),
					c,
					ArrayRef<unsigned>(idxs));
		}
		else
		{
			auto* i = InsertValueInst::Create(
					UndefValue::get(cmp),
					tmp,
					ArrayRef<unsigned>(idxs),
					"");
			auto* a = val == tmp ? after : cast<Instruction>(tmp);
			conv = insertBeforeAfter(i, before, a);
		}
	}
	else
	{
		errs() << "\nconvertValueToType(): unhandled type conversion\n";
		errs() << *val << "\n";
		errs() << *type << "\n\n";
		assert(false);
		conv = nullptr;
	}

	return conv;
}

} // anonymous namespace

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// IrModifier.
//==============================================================================
//

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

//
//==============================================================================
// IrModifier static methods.
//==============================================================================
//

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

llvm::AllocaInst* IrModifier::createAlloca(
		llvm::Function* fnc,
		llvm::Type* ty,
		const std::string& name)
{
	if (fnc->empty() || fnc->getEntryBlock().empty())
	{
		return nullptr;
	}

	return new AllocaInst(ty, name, &fnc->getEntryBlock().front());
}

/**
 * Create type conversion from provided value to provided type.
 * Created instructions are inserted before the specified instruction.
 * @param val Value to convert.
 * @param type Type to convert to.
 * @param before Instruction before which created conversion instructions
 *        are inserted.
 * @return Final value of the specified type.
 */
Value* IrModifier::convertValueToType(Value* val, Type* type, Instruction* before)
{
	return convertToType(val, type, before, nullptr, false);
}

/**
 * Create type conversion from provided value to provided type.
 * Created instructions are inserted after the specified instruction.
 * @param val Value to convert.
 * @param type Type to convert to.
 * @param after Instruction after which created conversion instructions
 *        are inserted.
 * @return Final value of the specified type.
 */
llvm::Value* IrModifier::convertValueToTypeAfter(
		llvm::Value* val,
		llvm::Type* type,
		llvm::Instruction* after)
{
	return convertToType(val, type, nullptr, after, false);
}

/**
 * This is the same as @c convertValueToType() but working with constants.
 * It does not insert constant expressions (type casts) to any particular place
 * in the IR. It just returns the created constant expressions.
 * @param val  Constant value to convert.
 * @param type Type to convert to.
 * @return Constant expression representing type conversion.
 */
Constant* IrModifier::convertConstantToType(Constant* val, Type* type)
{
	auto* v = convertToType(val, type, nullptr, nullptr, true);
	auto* c = dyn_cast_or_null<Constant>(v);
	if (v)
	{
		assert(c);
	}
	return c;
}

} // namespace bin2llvmir
} // namespace retdec
