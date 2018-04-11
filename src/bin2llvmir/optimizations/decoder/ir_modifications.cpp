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

	pseudo->removeFromParent();
	_pseudoCalls.emplace(pseudo, c);

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

	pseudo->removeFromParent();
	_pseudoCalls.emplace(pseudo, c);

	return c;
}

llvm::ReturnInst* Decoder::transformToReturn(llvm::CallInst* pseudo)
{
	auto* term = pseudo->getParent()->getTerminator();
	auto* r = ReturnInst::Create(
			pseudo->getModule()->getContext(),
			UndefValue::get(pseudo->getFunction()->getReturnType()),
			term);
	term->eraseFromParent();

	pseudo->removeFromParent();
	_pseudoCalls.emplace(pseudo, r);

	return r;
}

llvm::BranchInst* Decoder::transformToBranch(
		llvm::CallInst* pseudo,
		llvm::BasicBlock* branchee)
{
	auto* term = pseudo->getParent()->getTerminator();
	auto* br = BranchInst::Create(branchee, term);
	term->eraseFromParent();

	pseudo->removeFromParent();
	_pseudoCalls.emplace(pseudo, br);

	return br;
}

llvm::BranchInst* Decoder::transformToCondBranch(
		llvm::CallInst* pseudo,
		llvm::Value* cond,
		llvm::BasicBlock* trueBb,
		llvm::BasicBlock* falseBb)
{
	auto* term = pseudo->getParent()->getTerminator();
	auto* br = BranchInst::Create(trueBb, falseBb, cond, term);
	term->eraseFromParent();

	pseudo->removeFromParent();
	_pseudoCalls.emplace(pseudo, br);

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

	pseudo->removeFromParent();
	_pseudoCalls.emplace(pseudo, sw);

	return sw;
}

llvm::Function* Decoder::_splitFunctionOn(utils::Address addr)
{
	if (auto* bb = getBasicBlockAtAddress(addr))
	{
		return _splitFunctionOn(addr, bb);
	}
	else if (auto ai = AsmInstruction(_module, addr))
	{
		auto* oldBb = ai.getBasicBlock();
		auto* newBb = ai.makeStart(names::generateBasicBlockName(addr));
		addBasicBlock(addr, newBb);

		ReturnInst::Create(
				oldBb->getModule()->getContext(),
				UndefValue::get(oldBb->getParent()->getReturnType()),
				oldBb->getTerminator());
		oldBb->getTerminator()->eraseFromParent();

		return _splitFunctionOn(addr, newBb);
	}
	else if (auto* before = getBasicBlockBeforeAddress(addr))
	{
		auto* newBb = createBasicBlock(addr, before->getParent(), before);
		return _splitFunctionOn(addr, newBb);
	}
	else
	{
		return createFunction(addr);
	}
}

llvm::Function* Decoder::_splitFunctionOn(
		utils::Address addr,
		llvm::BasicBlock* bb)
{
	if (bb->getPrevNode() == nullptr)
	{
		return bb->getParent();
	}

	std::string name = _names->getPreferredNameForAddress(addr);
	if (name.empty())
	{
		names::generateFunctionName(addr, _config->getConfig().isIda());
	}

	Function* oldFnc = bb->getParent();

	Function* newFnc = Function::Create(
			FunctionType::get(oldFnc->getReturnType(), false),
			oldFnc->getLinkage(),
			name);
	oldFnc->getParent()->getFunctionList().insertAfter(
			oldFnc->getIterator(),
			newFnc);

	_addr2fnc[addr] = newFnc;
	_fnc2addr[newFnc] = addr;

	newFnc->getBasicBlockList().splice(
			newFnc->begin(),
			oldFnc->getBasicBlockList(),
			bb->getIterator(),
			oldFnc->getBasicBlockList().end());

	bool restart = true;
	while (restart)
	{
		restart = false;
		for (BasicBlock& b : *oldFnc)
		{
			for (Instruction& i : b)
			{
				if (BranchInst* br = dyn_cast<BranchInst>(&i))
				{
					if (br->isConditional())
					{
						// TODO: this is shit hack.
//						assert(br->getSuccessor(0)->getParent() == br->getFunction());
//						assert(br->getSuccessor(1)->getParent() == br->getFunction());

						if (br->getSuccessor(0)->getParent() != br->getFunction()
								|| br->getSuccessor(1)->getParent() != br->getFunction())
						{
							auto* r = ReturnInst::Create(
									br->getModule()->getContext(),
									UndefValue::get(br->getFunction()->getReturnType()),
									br);
							br->eraseFromParent();
							restart = true;
							break;
						}
					}
					else
					{
						BasicBlock* succ = br->getSuccessor(0);
						if (succ->getParent() != br->getFunction())
						{
							// Succ is first in function -> call function.
							if (succ->getPrevNode() == nullptr)
							{
								CallInst::Create(succ->getParent(), "", br);
								ReturnInst::Create(
										br->getModule()->getContext(),
										UndefValue::get(br->getFunction()->getReturnType()),
										br);
								br->eraseFromParent();
								break;
							}
							else
							{
								Address target = getBasicBlockAddress(succ);
								assert(target.isDefined());
								auto* nf = _splitFunctionOn(target, succ);

								CallInst::Create(nf, "", br);
								ReturnInst::Create(
										br->getModule()->getContext(),
										UndefValue::get(br->getFunction()->getReturnType()),
										br);
								br->eraseFromParent();
								restart = true;
								break;
							}
						}
					}
				}
				else if (SwitchInst* sw = dyn_cast<SwitchInst>(&i))
				{
					for (unsigned j = 0, e = sw->getNumSuccessors(); j != e; ++j)
					{
						assert(sw->getSuccessor(j)->getParent() == sw->getFunction());
					}
				}
			}

			if (restart)
			{
				break;
			}
		}
	}

	restart = true;
	while (restart)
	{
		restart = false;
		for (BasicBlock& b : *newFnc)
		{
			for (Instruction& i : b)
			{
				if (BranchInst* br = dyn_cast<BranchInst>(&i))
				{
					if (br->isConditional())
					{
						// TODO: this is shit hack.
//						assert(br->getSuccessor(0)->getParent() == br->getFunction());
//						assert(br->getSuccessor(1)->getParent() == br->getFunction());

						if (br->getSuccessor(0)->getParent() != br->getFunction()
								|| br->getSuccessor(1)->getParent() != br->getFunction())
						{
							auto* r = ReturnInst::Create(
									br->getModule()->getContext(),
									UndefValue::get(br->getFunction()->getReturnType()),
									br);
							br->eraseFromParent();
							restart = true;
							break;
						}
					}
					else
					{
						BasicBlock* succ = br->getSuccessor(0);
						if (succ->getParent() != br->getFunction())
						{
							// Succ is first in function -> call function.
							if (succ->getPrevNode() == nullptr)
							{
								CallInst::Create(succ->getParent(), "", br);
								ReturnInst::Create(
										br->getModule()->getContext(),
										UndefValue::get(br->getFunction()->getReturnType()),
										br);
								br->eraseFromParent();
								break;
							}
							else
							{
								Address target = getBasicBlockAddress(succ);
								assert(target.isDefined());
								auto* nf = _splitFunctionOn(target, succ);

								CallInst::Create(nf, "", br);
								ReturnInst::Create(
										br->getModule()->getContext(),
										UndefValue::get(br->getFunction()->getReturnType()),
										br);
								br->eraseFromParent();
								restart = true;
								break;
							}
						}
					}
				}
				else if (SwitchInst* sw = dyn_cast<SwitchInst>(&i))
				{
					for (unsigned j = 0, e = sw->getNumSuccessors(); j != e; ++j)
					{
						assert(sw->getSuccessor(j)->getParent() == sw->getFunction());
					}
				}
			}

			if (restart)
			{
				break;
			}
		}
	}

	return newFnc;
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

	assert(false);
	return nullptr;
}

} // namespace bin2llvmir
} // namespace retdec
