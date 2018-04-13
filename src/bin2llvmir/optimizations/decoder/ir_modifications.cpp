/**
* @file src/bin2llvmir/optimizations/decoder/ir_modifications.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

llvm::CallInst* Decoder::transformToCall(
		llvm::CallInst* pseudo,
		llvm::Function* callee)
{
	auto* c = CallInst::Create(callee);
	c->insertAfter(pseudo);

	if (auto* retObj = getCallReturnObject())
	{
		auto* cc = cast<Instruction>(
				convertValueToTypeAfter(c, retObj->getValueType(), c));
		auto* s = new StoreInst(cc, retObj);
		s->insertAfter(cc);
	}

	return c;
}

llvm::CallInst* Decoder::transformToCondCall(
		llvm::CallInst* pseudo,
		llvm::Value* cond,
		llvm::Function* callee,
		llvm::BasicBlock* falseBb)
{
	auto* oldBb = pseudo->getParent();
	auto* newBb = oldBb->splitBasicBlock(pseudo);
	// We do NOT want to name or give address to this block.

	auto* oldTerm = oldBb->getTerminator();
	BranchInst::Create(newBb, falseBb, cond, oldTerm);
	oldTerm->eraseFromParent();

	auto* newTerm = newBb->getTerminator();
	BranchInst::Create(falseBb, newTerm);
	newTerm->eraseFromParent();

	auto* c = CallInst::Create(callee);
	c->insertAfter(pseudo);

	return c;
}

llvm::ReturnInst* Decoder::transformToReturn(llvm::CallInst* pseudo)
{
	auto* term = pseudo->getParent()->getTerminator();
	assert(pseudo->getNextNode() == term);
	auto* r = ReturnInst::Create(
			pseudo->getModule()->getContext(),
			UndefValue::get(pseudo->getFunction()->getReturnType()),
			term);
	term->eraseFromParent();

	return r;
}

llvm::BranchInst* Decoder::transformToBranch(
		llvm::CallInst* pseudo,
		llvm::BasicBlock* branchee)
{
	auto* term = pseudo->getParent()->getTerminator();
	assert(pseudo->getNextNode() == term);
	auto* br = BranchInst::Create(branchee, term);
	term->eraseFromParent();

	return br;
}

llvm::BranchInst* Decoder::transformToCondBranch(
		llvm::CallInst* pseudo,
		llvm::Value* cond,
		llvm::BasicBlock* trueBb,
		llvm::BasicBlock* falseBb)
{
	auto* term = pseudo->getParent()->getTerminator();
	assert(pseudo->getNextNode() == term);
	auto* br = BranchInst::Create(trueBb, falseBb, cond, term);
	term->eraseFromParent();

	return br;
}

llvm::SwitchInst* Decoder::transformToSwitch(
		llvm::CallInst* pseudo,
		llvm::Value* val,
		llvm::BasicBlock* defaultBb,
		const std::vector<llvm::BasicBlock*>& cases)
{
	unsigned numCases = 0;
	for (auto* c : cases)
	{
		if (c != defaultBb)
		{
			++numCases;
		}
	}

	auto* term = pseudo->getParent()->getTerminator();
	assert(pseudo->getNextNode() == term);
	auto* intType = cast<IntegerType>(val->getType());
	auto* sw = SwitchInst::Create(val, defaultBb, numCases, term);
	unsigned cntr = 0;
	for (auto& c : cases)
	{
		if (c != defaultBb)
		{
			sw->addCase(ConstantInt::get(intType, cntr), c);
		}
		++cntr;
	}
	term->eraseFromParent();

	return sw;
}

/**
 * TODO: This will be replaced by a proper ABI provider.
 */
llvm::GlobalVariable* Decoder::getCallReturnObject()
{
	if (_config->getConfig().architecture.isX86_32())
	{
		return _module->getNamedGlobal("eax");
	}
	else if (_config->getConfig().architecture.isX86_64())
	{
		return _module->getNamedGlobal("rax");
	}
	else if (_config->isMipsOrPic32())
	{
		return _config->getLlvmRegister("v0");
	}
	else if (_config->getConfig().architecture.isPpc())
	{
		return _config->getLlvmRegister("r3");
	}
	else if (_config->getConfig().architecture.isArmOrThumb())
	{
		return _config->getLlvmRegister("r0");
	}

	assert(false);
	return nullptr;
}

/**
 * \return \c True if it is allowed to split function on basic block \p bb.
 */
bool Decoder::canSplitFunctionOn(llvm::BasicBlock* bb)
{
	for (auto* u : bb->users())
	{
		// All users must be branch instructions.
		//
		auto* br = dyn_cast<BranchInst>(u);
		if (br == nullptr)
		{
			return false;
		}

		// BB must be true branch in all users.
		//
		if (br->getSuccessor(0) != bb)
		{
			return false;
		}
	}

	return true;
}

/**
 * \return \c True if it is allowed to split function on basic block \p bb.
 */
bool Decoder::canSplitFunctionOn(
		utils::Address addr,
		llvm::BasicBlock* splitBb,
		std::set<llvm::BasicBlock*>& newFncStarts)
{
	newFncStarts.insert(splitBb);

	auto* f = splitBb->getParent();
	auto fAddr = getFunctionAddress(f);

	std::set<Address> fncStarts;
	fncStarts.insert(fAddr);
	fncStarts.insert(addr);

	bool changed = true;
	while (changed)
	{
		changed = false;
		for (BasicBlock& b : *f)
		{
			Address bAddr = getBasicBlockAddress(&b);
			auto up = fncStarts.upper_bound(bAddr);
			--up;
			Address bFnc = *up;

			for (auto* p : predecessors(&b))
			{
				Address pAddr = getBasicBlockAddress(p);
				auto up = fncStarts.upper_bound(pAddr);
				--up;
				Address pFnc = *up;

				if (bFnc != pFnc)
				{
					if (!canSplitFunctionOn(&b))
					{
						return false;
					}

					newFncStarts.insert(&b);
					fncStarts.insert(bAddr);
					changed = true;
				}
			}
		}
	}

	return true;
}

/**
 * This can create new BB at \p addr even if it then cannot split function
 * on this new BB. Is this desirable behavior?
 */
llvm::Function* Decoder::splitFunctionOn(utils::Address addr)
{
	if (auto* bb = getBasicBlockAtAddress(addr))
	{
		return bb->getPrevNode()
				? splitFunctionOn(addr, bb)
				: bb->getParent();
	}
	// There is an instruction at address, but not BB -> do not split
	// existing blocks to create functions.
	//
	else if (auto ai = AsmInstruction(_module, addr))
	{
		return nullptr;
	}
	else if (auto* f = getFunctionContainingAddress(addr))
	{
		auto* before = getBasicBlockBeforeAddress(addr);
		assert(before);
		auto* newBb = createBasicBlock(addr, before->getParent(), before);
		return splitFunctionOn(addr, newBb);
	}
	else
	{
		return createFunction(addr);
	}
}

llvm::Function* Decoder::splitFunctionOn(
		utils::Address addr,
		llvm::BasicBlock* splitOnBb)
{
	if (splitOnBb->getPrevNode() == nullptr)
	{
		return splitOnBb->getParent();
	}

	std::set<BasicBlock*> newFncStarts;
	if (!canSplitFunctionOn(addr, splitOnBb, newFncStarts))
	{
		return nullptr;
	}

	llvm::Function* ret = nullptr;
	std::set<Function*> newFncs;
	for (auto* splitBb : newFncStarts)
	{
		Address splitAddr = getBasicBlockAddress(splitBb);

		std::string name = _names->getPreferredNameForAddress(splitAddr);
		if (name.empty())
		{
			name = names::generateFunctionName(addr, _config->getConfig().isIda());
		}

		Function* oldFnc = splitBb->getParent();
		Function* newFnc = Function::Create(
				FunctionType::get(oldFnc->getReturnType(), false),
				oldFnc->getLinkage(),
				name);
		oldFnc->getParent()->getFunctionList().insertAfter(
				oldFnc->getIterator(),
				newFnc);

		addFunction(splitAddr, newFnc);

		newFnc->getBasicBlockList().splice(
				newFnc->begin(),
				oldFnc->getBasicBlockList(),
				splitBb->getIterator(),
				oldFnc->getBasicBlockList().end());

		newFncs.insert(newFnc);
		if (splitOnBb == splitBb)
		{
			ret = newFnc;
		}
	}
	assert(ret);

	for (Function* f : newFncs)
	for (BasicBlock& b : *f)
	{
		auto* br = dyn_cast<BranchInst>(b.getTerminator());
		if (br && br->getSuccessor(0)->getParent() != br->getFunction())
		{
			auto* callee = br->getSuccessor(0)->getParent();
			auto* c = CallInst::Create(callee, "", br);
			if (auto* retObj = getCallReturnObject())
			{
				auto* cc = cast<Instruction>(
						convertValueToTypeAfter(c, retObj->getValueType(), c));
				auto* s = new StoreInst(cc, retObj);
				s->insertAfter(cc);
			}

			ReturnInst::Create(
					br->getModule()->getContext(),
					UndefValue::get(br->getFunction()->getReturnType()),
					br);
			br->eraseFromParent();
		}

		// Test.
		for (auto* s : successors(&b))
		{
			assert(b.getParent() == s->getParent());
		}
	}

	return ret;
}

} // namespace bin2llvmir
} // namespace retdec
