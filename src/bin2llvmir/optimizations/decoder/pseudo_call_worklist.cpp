/**
* @file src/bin2llvmir/optimizations/decoder/jump_targets.cpp
* @brief Worklist of pseudo calls that need to be solved.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/InstIterator.h>

#include "retdec/bin2llvmir/optimizations/decoder/pseudo_call_worklist.h"

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// PseudoCallWorklist
//==============================================================================
//

PseudoCall::PseudoCall(eType t, llvm::CallInst* c) :
		type(t),
		pseudoCall(c)
{

}

//
//==============================================================================
// PseudoCallWorklist
//==============================================================================
//

void PseudoCallWorklist::addPseudoCall(llvm::CallInst* c)
{
	_worklist.emplace(c, PseudoCall(PseudoCall::eType::CALL, c));
}

void PseudoCallWorklist::addPseudoBr(llvm::CallInst* c)
{
	_worklist.emplace(c, PseudoCall(PseudoCall::eType::BR, c));
}

void PseudoCallWorklist::addPseudoCondBr(llvm::CallInst* c)
{
	_worklist.emplace(c, PseudoCall(PseudoCall::eType::COND_BR, c));
}

void PseudoCallWorklist::addPseudoReturn(llvm::CallInst* c)
{
	// TODO: right now, we replace return right away,
	// this could be done later.
//	_worklist.emplace(c, PseudoCall(PseudoCall::eType::RETURN, c));

	auto* f = c->getFunction();
	auto* r = llvm::ReturnInst::Create(
			c->getModule()->getContext(),
			llvm::UndefValue::get(f->getReturnType()),
			c);
	c->eraseFromParent();

	auto* ret = r->getNextNode();
	assert(llvm::isa<llvm::ReturnInst>(ret));
	ret->eraseFromParent();
}

void PseudoCallWorklist::setTargetFunction(llvm::CallInst* c, llvm::Function* f)
{
	auto fIt = _worklist.find(c);
	if (fIt == _worklist.end())
	{
		assert(false);
		return;
	}
	PseudoCall& pc = fIt->second;

	assert(pc.type == PseudoCall::eType::CALL || pc.type == PseudoCall::eType::BR);

	llvm::CallInst::Create(f, "", pc.pseudoCall);
	pc.pseudoCall->eraseFromParent();
	_worklist.erase(pc.pseudoCall);
}

void PseudoCallWorklist::setTargetBbTrue(llvm::CallInst* c, llvm::BasicBlock* b)
{
	auto fIt = _worklist.find(c);
	if (fIt == _worklist.end())
	{
		assert(false);
		return;
	}
	PseudoCall& pc = fIt->second;

	assert(pc.type == PseudoCall::eType::BR || pc.type == PseudoCall::eType::COND_BR);

	pc.targetBbTrue = b;

	if (pc.type == PseudoCall::eType::BR
			&& pc.pseudoCall->getFunction() == pc.targetBbTrue->getParent())
	{
		auto* br = llvm::BranchInst::Create(pc.targetBbTrue, pc.pseudoCall);
		pc.pseudoCall->eraseFromParent();
		_worklist.erase(pc.pseudoCall);

		auto* ret = br->getNextNode();
		assert(llvm::isa<llvm::ReturnInst>(ret));
		ret->eraseFromParent();
	}
	else if (pc.type == PseudoCall::eType::BR)
	{
		auto* call = llvm::CallInst::Create(b->getParent(), "", pc.pseudoCall);
		pc.pseudoCall->eraseFromParent();
		_worklist.erase(pc.pseudoCall);

		auto* ret = call->getNextNode();
		assert(llvm::isa<llvm::ReturnInst>(ret));
		ret->eraseFromParent();
	}
	else if (pc.type == PseudoCall::eType::COND_BR && pc.targetBbFalse
			&& pc.pseudoCall->getFunction() == pc.targetBbTrue->getParent()
			&& pc.pseudoCall->getFunction() == pc.targetBbFalse->getParent())
	{
		auto* br = llvm::BranchInst::Create(
				pc.targetBbTrue,
				pc.targetBbFalse,
				pc.pseudoCall->getOperand(0),
				pc.pseudoCall);
		pc.pseudoCall->eraseFromParent();
		_worklist.erase(pc.pseudoCall);

		auto* ret = br->getNextNode();
		assert(llvm::isa<llvm::ReturnInst>(ret));
		ret->eraseFromParent();
	}
	else if (pc.type == PseudoCall::eType::COND_BR && pc.targetBbFalse)
	{
		assert(false && "cond br to a different fnc");
	}
}

void PseudoCallWorklist::setTargetBbFalse(llvm::CallInst* c, llvm::BasicBlock* b)
{
	auto fIt = _worklist.find(c);
	if (fIt == _worklist.end())
	{
		assert(false);
		return;
	}
	PseudoCall& pc = fIt->second;

	assert(pc.type == PseudoCall::eType::COND_BR);

	pc.targetBbFalse = b;

	if (pc.targetBbTrue
			&& pc.pseudoCall->getFunction() == pc.targetBbTrue->getParent()
			&& pc.pseudoCall->getFunction() == pc.targetBbFalse->getParent())
	{
		auto* br = llvm::BranchInst::Create(
				pc.targetBbTrue,
				pc.targetBbFalse,
				pc.pseudoCall->getOperand(0),
				pc.pseudoCall);
		pc.pseudoCall->eraseFromParent();
		_worklist.erase(pc.pseudoCall);

		auto* ret = br->getNextNode();
		assert(llvm::isa<llvm::ReturnInst>(ret));
		ret->eraseFromParent();
	}
	else if (pc.targetBbTrue)
	{
		assert(false && "cond br to a different fnc");
	}
}

} // namespace bin2llvmir
} // namespace retdec
