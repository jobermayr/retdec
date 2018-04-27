/**
* @file src/bin2llvmir/optimizations/stack/stack.cpp
* @brief Reconstruct stack.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/optimizations/stack/stack.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/utils.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char StackAnalysis::ID = 0;

static RegisterPass<StackAnalysis> X(
		"stack",
		"Stack optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

StackAnalysis::StackAnalysis() :
		ModulePass(ID)
{

}

bool StackAnalysis::runOnModule(llvm::Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_dbgf = DebugFormatProvider::getDebugFormat(_module);
	return run();
}

bool StackAnalysis::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		DebugFormat* dbgf)
{
	_module = &m;
	_config = c;
	_dbgf = dbgf;
	return run();
}

bool StackAnalysis::run()
{
	if (_config == nullptr)
	{
		return false;
	}

	ReachingDefinitionsAnalysis RDA;
	RDA.runOnModule(*_module, _config);

	for (auto& f : *_module)
	{
		runOnFunction(RDA, &f);
	}

	return true;
}

void StackAnalysis::runOnFunction(
		ReachingDefinitionsAnalysis& RDA,
		llvm::Function* f)
{
	LOG << "\tfunction : " << f->getName().str() << std::endl;

	std::map<Value*, Value*> val2val;
	std::list<ReplaceItem> replaceItems;

	for (auto &bb : *f)
	for (auto &i : bb)
	{
		if (StoreInst *store = dyn_cast<StoreInst>(&i))
		{
			if (AsmInstruction::isLlvmToAsmInstruction(store))
			{
				continue;
			}

			handleInstruction(
					RDA,
					store,
					store->getValueOperand(),
					store->getValueOperand()->getType(),
					replaceItems,
					val2val);

			if (isa<GlobalVariable>(store->getPointerOperand()))
			{
				continue;
			}

			handleInstruction(
					RDA,
					store,
					store->getPointerOperand(),
					store->getValueOperand()->getType(),
					replaceItems,
					val2val);
		}
		else if (LoadInst* load = dyn_cast<LoadInst>(&i))
		{
			if (isa<GlobalVariable>(load->getPointerOperand()))
			{
				continue;
			}

			handleInstruction(
					RDA,
					load,
					load->getPointerOperand(),
					load->getType(),
					replaceItems,
					val2val);
		}
	}

	std::set<Instruction*> toErase;
	for (auto& ri : replaceItems)
	{
		auto* s = dyn_cast<StoreInst>(ri.inst);
		auto* l = dyn_cast<LoadInst>(ri.inst);
		if (s && s->getPointerOperand() == ri.from)
		{
			auto* conv = convertValueToType(
					s->getValueOperand(),
					ri.to->getType()->getElementType(),
					ri.inst);
			new StoreInst(conv, ri.to, ri.inst);
			toErase.insert(s);
		}
		else if (l && l->getPointerOperand() == ri.from)
		{
			auto* nl = new LoadInst(ri.to, "", l);
			auto* conv = convertValueToType(nl, l->getType(), l);
			l->replaceAllUsesWith(conv);
			toErase.insert(l);
		}
		else
		{
			auto* conv = convertValueToType(ri.to, ri.from->getType(), ri.inst);
			ri.inst->replaceUsesOfWith(ri.from, conv);
		}
	}
	for (auto* e : toErase)
	{
		e->eraseFromParent();
	}
}

void StackAnalysis::handleInstruction(
		ReachingDefinitionsAnalysis& RDA,
		llvm::Instruction* inst,
		llvm::Value* val,
		llvm::Type* type,
		std::list<ReplaceItem>& replaceItems,
		std::map<llvm::Value*, llvm::Value*>& val2val)
{
	LOG << "@ " << AsmInstruction::getInstructionAddress(inst)
			<< " -- " << llvmObjToString(inst) << std::endl;

	if (val->getType()->isIntegerTy(1)
			|| (val->getType()->isPointerTy()
			&& val->getType()->getPointerElementType()->isIntegerTy(1)))
	{
		return;
	}

	SymbolicTree root(RDA, val, &val2val);
	LOG << root << std::endl;

	if (!root.isVal2ValMapUsed())
	{
		bool stackPtr = false;
		for (SymbolicTree* n : root.getPostOrder())
		{
			if (_config->isStackPointerRegister(n->value))
			{
				stackPtr = true;
				break;
			}
		}
		if (!stackPtr)
		{
			LOG << "===> no SP" << std::endl;
			return;
		}
	}

	auto* debugSv = getDebugStackVariable(inst->getFunction(), root);

	root.simplifyNode(_config);
	LOG << root << std::endl;

	if (debugSv == nullptr)
	{
		debugSv = getDebugStackVariable(inst->getFunction(), root);
	}

	auto* ci = dyn_cast_or_null<ConstantInt>(root.value);
	if (ci == nullptr)
	{
		return;
	}

	if (auto* s = dyn_cast<StoreInst>(inst))
	{
		if (s->getValueOperand() == val)
		{
			val2val[inst] = ci;
		}
	}

	LOG << "===> " << llvmObjToString(ci) << std::endl;
	LOG << "===> " << ci->getSExtValue() << std::endl;

	std::string name = debugSv ? debugSv->getName() : "";
	Type* t = debugSv ?
			stringToLlvmTypeDefault(_module, debugSv->type.getLlvmIr()) :
			type;

	IrModifier irModif(_module, _config);
	auto p = irModif.getStackVariable(
			inst->getFunction(),
			ci->getSExtValue(),
			t,
			name);

	AllocaInst* a = p.first;
	auto* ca = p.second;

	if (debugSv)
	{
		ca->setIsFromDebug(true);
		ca->setRealName(debugSv->getName());
	}

	replaceItems.push_back(ReplaceItem{inst, val, a});

	LOG << "===> " << llvmObjToString(a) << std::endl;
	LOG << "===> " << llvmObjToString(inst) << std::endl;
	LOG << std::endl;
}

/**
 * Find a value that is being added to the stack pointer register in \p root.
 * Find a debug variable with offset equal to this value.
 */
retdec::config::Object* StackAnalysis::getDebugStackVariable(
		llvm::Function* fnc,
		SymbolicTree& root)
{
	if (_dbgf == nullptr)
	{
		return nullptr;
	}
	auto* debugFnc = _dbgf->getFunction(_config->getFunctionAddress(fnc));
	if (debugFnc == nullptr)
	{
		return nullptr;
	}

	retdec::utils::Maybe<int> baseOffset;
	if (auto* ci = dyn_cast_or_null<ConstantInt>(root.value))
	{
		baseOffset = ci->getSExtValue();
	}
	else
	{
		for (SymbolicTree* n : root.getLevelOrder())
		{
			if (isa<AddOperator>(n->value)
					&& n->ops.size() == 2
					&& isa<LoadInst>(n->ops[0].value)
					&& isa<ConstantInt>(n->ops[1].value))
			{
				auto* l = cast<LoadInst>(n->ops[0].value);
				auto* ci = cast<ConstantInt>(n->ops[1].value);
				if (_config->isRegister(l->getPointerOperand()))
				{
					baseOffset = ci->getSExtValue();
				}
				break;
			}
		}
	}
	if (baseOffset.isUndefined())
	{
		return nullptr;
	}

	for (auto& p : debugFnc->locals)
	{
		auto& var = p.second;
		if (!var.getStorage().isStack())
		{
			continue;
		}
		if (var.getStorage().getStackOffset() == baseOffset)
		{
			return &var;
		}
	}

	return nullptr;
}

} // namespace bin2llvmir
} // namespace retdec
