/**
 * @file src/bin2llvmir/optimizations/asm_inst_optimizer/x86.cpp
 * @brief Optimize a single x86 assembly instruction.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/PatternMatch.h>

#include "retdec/bin2llvmir/optimizations/asm_inst_opt/x86.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace asm_inst_opt {

bool optimize_stosX(AsmInstruction ai, cs_insn* ci, cs_x86* xi)
{
	if (!((ci->id == X86_INS_STOSB
			|| ci->id == X86_INS_STOSW
			|| ci->id == X86_INS_STOSD)
			&& xi->prefix[0] == X86_PREFIX_REP))
	{
		return false;
	}

	auto& ctx = ai.getContext();
	auto* module = ai.getModule();

	auto* eax = module->getNamedGlobal("eax");
	auto* edi = module->getNamedGlobal("edi");
	auto* ecx = module->getNamedGlobal("ecx");
	if (!eax || !edi || !ecx)
	{
		return false;
	}

	std::vector<Type*> params = {
			PointerType::get(Type::getInt8Ty(ctx), 0),
			Type::getInt32Ty(ctx),
			ecx->getValueType()};
	FunctionType* ft = FunctionType::get(
			PointerType::get(Type::getInt8Ty(ctx), 0),
			params,
			false);

	// TODO: Many functions are created in the new decoder, but
	// their types are not set at the moment.
	// Therefore, if memset is created, it does not have the type
	// needed here. Right now, we create new memset variant,
	// but it would be better if decoder created fncs with good
	// types, so it can be used here directly.
	// TODO: the same for all other functions.
	//
	static Function* fnc = nullptr;
	if (fnc == nullptr)
	{
		fnc = module->getFunction("memset");
		if (fnc == nullptr || fnc->getFunctionType() != ft)
		{
			fnc = Function::Create(
					ft,
					GlobalValue::ExternalLinkage,
					"_memset",
					module);
		}
	}
	if (fnc == nullptr || fnc->getFunctionType() != ft)
	{
		return false;
	}

	if (!ai.eraseInstructions())
	{
		return false;
	}

	std::vector<Value*> args;
	auto* l0 = ai.insertBackSafe(new LoadInst(edi));
	auto* l1 = ai.insertBackSafe(new LoadInst(eax));
	auto* l2 = ai.insertBackSafe(new LoadInst(ecx));
	args.push_back(convertValueToTypeAfter(l0, params[0], l2));
	args.push_back(convertValueToTypeAfter(l1, params[1], l2));
	args.push_back(convertValueToTypeAfter(l2, params[2], l2));
	auto* call = ai.insertBackSafe(CallInst::Create(fnc, args));
	auto* conv = convertValueToTypeAfter(
			call,
			ecx->getType()->getElementType(),
			call);
	ai.insertBackSafe(new StoreInst(conv, ecx));

	return true;
}

bool optimize_cmpsX(AsmInstruction ai, cs_insn* ci, cs_x86* xi)
{
	if (!((ci->id == X86_INS_CMPSB
			|| ci->id == X86_INS_CMPSW
			|| ci->id == X86_INS_CMPSD)
			&& xi->prefix[0] == X86_PREFIX_REP))
	{
		return false;
	}

	auto& ctx = ai.getContext();
	auto* module = ai.getModule();

	auto* edi = module->getNamedGlobal("edi");
	auto* ecx = module->getNamedGlobal("ecx");
	auto* esi = module->getNamedGlobal("esi");
	auto* zf = module->getNamedGlobal("zf");
	if (!edi || !ecx || !esi || !zf)
	{
		return false;
	}

	std::vector<Type*> params = {
			PointerType::get(Type::getInt8Ty(ctx), 0),
			PointerType::get(Type::getInt8Ty(ctx), 0),
			ecx->getValueType()};
	FunctionType* ft = FunctionType::get(
			Type::getInt32Ty(ctx),
			params,
			false);

	static Function* fnc = nullptr;
	if (fnc == nullptr)
	{
		fnc = module->getFunction("strncmp");
		if (fnc == nullptr || fnc->getFunctionType() != ft)
		{
			fnc = Function::Create(
					ft,
					GlobalValue::ExternalLinkage,
					"_strncmp",
					module);
		}
	}
	if (fnc == nullptr || fnc->getFunctionType() != ft)
	{
		return false;
	}

	if (!ai.eraseInstructions())
	{
		return false;
	}

	std::vector<Value*> args;
	auto* l0 = ai.insertBackSafe(new LoadInst(esi));
	auto* l1 = ai.insertBackSafe(new LoadInst(edi));
	auto* l2 = ai.insertBackSafe(new LoadInst(ecx));
	args.push_back(convertValueToTypeAfter(l0, params[0], l2));
	args.push_back(convertValueToTypeAfter(l1, params[1], l2));
	args.push_back(convertValueToTypeAfter(l2, params[2], l2));
	auto* call = ai.insertBackSafe(CallInst::Create(fnc, args));
	auto* conv = convertValueToTypeAfter(
			call,
			ecx->getType()->getElementType(),
			call);
	ai.insertBackSafe(new StoreInst(conv, ecx));
	auto* trunc = ai.insertBackSafe(CastInst::CreateTruncOrBitCast(
			conv,
			Type::getInt1Ty(ctx)));
	auto* xorOp = ai.insertBackSafe(BinaryOperator::CreateXor(
			trunc,
			ConstantInt::get(trunc->getType(), 1)));
	ai.insertBackSafe(new StoreInst(xorOp, zf));

	return true;
}

bool optimize_movsX(AsmInstruction ai, cs_insn* ci, cs_x86* xi)
{
	if (!((ci->id == X86_INS_MOVSB
			|| ci->id == X86_INS_MOVSW
			|| ci->id == X86_INS_MOVSD)
			&& xi->prefix[0] == X86_PREFIX_REP))
	{
		return false;
	}

	auto& ctx = ai.getContext();
	auto* module = ai.getModule();

	auto* edi = module->getNamedGlobal("edi");
	auto* ecx = module->getNamedGlobal("ecx");
	auto* esi = module->getNamedGlobal("esi");
	if (!edi || !ecx || !esi)
	{
		return false;
	}

	std::vector<Type*> params = {
			PointerType::get(Type::getInt8Ty(ctx), 0),
			PointerType::get(Type::getInt8Ty(ctx), 0),
			ecx->getValueType()};
	FunctionType* ft = FunctionType::get(
			PointerType::get(Type::getInt8Ty(ctx), 0),
			params,
			false);

	static Function* fnc = nullptr;
	if (fnc == nullptr)
	{
		fnc = module->getFunction("memcpy");
		if (fnc == nullptr || fnc->getFunctionType() != ft)
		{
			fnc = Function::Create(
					ft,
					GlobalValue::ExternalLinkage,
					"_memcpy",
					module);
		}
	}
	if (fnc == nullptr || fnc->getFunctionType() != ft)
	{
		return false;
	}

	if (!ai.eraseInstructions())
	{
		return false;
	}

	std::vector<Value*> args;
	auto* l0 = ai.insertBackSafe(new LoadInst(edi));
	auto* l1 = ai.insertBackSafe(new LoadInst(esi));
	auto* l2 = ai.insertBackSafe(new LoadInst(ecx));
	args.push_back(convertValueToTypeAfter(l0, params[0], l2));
	args.push_back(convertValueToTypeAfter(l1, params[1], l2));
	args.push_back(convertValueToTypeAfter(l2, params[2], l2));
	auto* call = ai.insertBackSafe(CallInst::Create(fnc, args));
	auto* conv = convertValueToTypeAfter(
			call,
			ecx->getType()->getElementType(),
			call);
	ai.insertBackSafe(new StoreInst(conv, ecx));

	return true;
}

bool optimize_scasX(AsmInstruction ai, cs_insn* ci, cs_x86* xi)
{
	if (!((ci->id == X86_INS_SCASB
			|| ci->id == X86_INS_SCASW
			|| ci->id == X86_INS_SCASD)
			&& xi->prefix[0] == X86_PREFIX_REPNE))
	{
		return false;
	}

	auto& ctx = ai.getContext();
	auto* module = ai.getModule();

	auto* edi = module->getNamedGlobal("edi");
	auto* ecx = module->getNamedGlobal("ecx");
	if (!edi || !ecx)
	{
		return false;
	}

	std::vector<Type*> params = {
			PointerType::get(Type::getInt8Ty(ctx), 0)};
	FunctionType* ft = FunctionType::get(
			ecx->getValueType(),
			params,
			false);

	static Function* fnc = nullptr;
	if (fnc == nullptr)
	{
		fnc = module->getFunction("strlen");
		if (fnc == nullptr || fnc->getFunctionType() != ft)
		{
			fnc = Function::Create(
					ft,
					GlobalValue::ExternalLinkage,
					"_strlen",
					module);
		}
	}
	if (fnc == nullptr || fnc->getFunctionType() != ft)
	{
		return false;
	}

	if (!ai.eraseInstructions())
	{
		return false;
	}

	std::vector<Value*> args;
	auto* l0 = ai.insertBackSafe(new LoadInst(edi));
	args.push_back(convertValueToTypeAfter(l0, params[0], l0));
	auto* call = ai.insertBackSafe(CallInst::Create(fnc, args));
	auto* mul = ai.insertBackSafe(BinaryOperator::CreateMul(
			call,
			ConstantInt::get(call->getType(), -1, true)));
	auto* add = ai.insertBackSafe(BinaryOperator::CreateSub(
			mul,
			ConstantInt::get(mul->getType(), 2)));
	auto* conv = convertValueToTypeAfter(
			add,
			ecx->getType()->getElementType(),
			add);
	ai.insertBackSafe(new StoreInst(conv, ecx));

	return true;
}

bool optimize_x86(AsmInstruction ai)
{
	cs_insn* ci = ai.getCapstoneInsn();
	cs_x86* xi = &ci->detail->x86;

	bool changed = false;

	changed |= optimize_stosX(ai, ci, xi);
	changed |= optimize_cmpsX(ai, ci, xi);
	changed |= optimize_movsX(ai, ci, xi);
	changed |= optimize_scasX(ai, ci, xi);

	return changed;
}

} // namespace asm_inst_opt
} // namespace bin2llvmir
} // namespace retdec
