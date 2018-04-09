/**
* @file src/bin2llvmir/optimizations/decoder/decoder.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <json/json.h>

#include <llvm/IR/Dominators.h>
#include <llvm/IR/PatternMatch.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/utils/capstone.h"
#include "retdec/bin2llvmir/utils/instruction.h"
#include "retdec/bin2llvmir/utils/type.h"
#include "retdec/bin2llvmir/utils/utils.h"

using namespace retdec::utils;
using namespace retdec::capstone2llvmir;
using namespace llvm;
using namespace llvm::PatternMatch;
using namespace retdec::fileformat;

namespace retdec {
namespace bin2llvmir {

char Decoder::ID = 0;

static RegisterPass<Decoder> X(
		"decoder",
		"Input binary to LLVM IR decoding",
		false, // Only looks at CFG
		false // Analysis Pass
);

Decoder::Decoder() :
		ModulePass(ID)
{

}

Decoder::~Decoder()
{
	cs_free(_dryCsInsn, 1);
}

bool Decoder::runOnModule(Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_image = FileImageProvider::getFileImage(_module);
	_debug = DebugFormatProvider::getDebugFormat(_module);
	_llvm2capstone = &AsmInstruction::getLlvmToCapstoneInsnMap(_module);
	_names = NamesProvider::getNames(_module);
	return runCatcher();
}

bool Decoder::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		FileImage* o,
		DebugFormat* d,
		NameContainer* n)
{
	_module = &m;
	_config = c;
	_image = o;
	_debug = d;
	_names = n;
	_llvm2capstone = &AsmInstruction::getLlvmToCapstoneInsnMap(_module);
	return runCatcher();
}

bool Decoder::runCatcher()
{
	try
	{
		return run();
	}
	catch (const Capstone2LlvmIrBaseError& e)
	{
		LOG << "[capstone2llvmir]: " << e.what() << std::endl;
		return false;
	}
}

bool Decoder::run()
{
	if (_config == nullptr || _image == nullptr)
	{
		LOG << "[ABORT] Config or object image is not available.\n";
		return false;
	}

	initTranslator();
	initDryRunCsInstruction();
	initEnvironment();
	initRanges();
	initJumpTargets();

	LOG << _ranges << std::endl;
	LOG << _jumpTargets << std::endl;

	decode();
	patternsRecognize();

dumpControFlowToJson(_module);
dumpModuleToFile(_module);

	removePseudoCalls();
	initConfigFunction();

dumpModuleToFile(_module);

	return false;
}

void Decoder::decode()
{
	LOG << "\n" << "doDecoding():" << std::endl;

	JumpTarget jt;
	while (getJumpTarget(jt))
	{
		LOG << "\t" << "processing : " << jt << std::endl;
		decodeJumpTarget(jt);
	}
}

bool Decoder::getJumpTarget(JumpTarget& jt)
{
	if (!_jumpTargets.empty())
	{
		jt = _jumpTargets.top();
		_jumpTargets.pop();
		return true;
	}
	else if (!_ranges.primaryEmpty())
	{
		jt = JumpTarget(
				_ranges.primaryFront().getStart(),
				JumpTarget::eType::LEFTOVER,
				CS_MODE_BIG_ENDIAN,
				Address());
		return true;
	}
	return false;
}

void Decoder::decodeJumpTarget(const JumpTarget& jt)
{
	const Address start = jt.getAddress();
	if (start.isUndefined())
	{
		LOG << "\t\t" << "unknown target address -> skip" << std::endl;
		return;
	}

	auto* range = jt.getType() < JumpTarget::eType::LEFTOVER
			? _ranges.get(start)
			: _ranges.getPrimary(start);
	if (range == nullptr)
	{
		LOG << "\t\t" << "found no range -> skip" << std::endl;
		return;
	}
	LOG << "\t\t" << "found range = " << *range << std::endl;

	auto bytes = _image->getImage()->getRawSegmentData(start);
	if (bytes.first == nullptr)
	{
		LOG << "\t\t" << "found no data -> skip" << std::endl;
		return;
	}

	auto toRangeEnd = range->getEnd() + 1 - start;
	bytes.second = toRangeEnd < bytes.second ? toRangeEnd : bytes.second;
	if (jt.hasSize() && jt.getSize() < bytes.second)
	{
		bytes.second = jt.getSize();
	}
	if (auto nextBbAddr = getBasicBlockAddressAfter(start))
	{
		auto sz = nextBbAddr - start;
		bytes.second = sz < bytes.second ? sz : bytes.second;
	}
	else if (auto nextFncAddr = getFunctionAddressAfter(start))
	{
		auto sz = nextFncAddr - start;
		bytes.second = sz < bytes.second ? sz : bytes.second;
	}

	if (jt.getType() == JumpTarget::eType::LEFTOVER)
	if (auto skipSz = decodeJumpTargetDryRun(jt, bytes))
	{
		AddressRange sr(start, start+skipSz-1);
		LOG << "\t\t" << "dry run failed -> skip range = " << sr << std::endl;
		_ranges.remove(sr);
		return;
	}

	BasicBlock* bb = getBasicBlockAtAddress(start);
	if (bb == nullptr)
	{
		if (jt.getType() != JumpTarget::eType::LEFTOVER)
		{
			LOG << "\t\t" << "found no bb for jt -> skip" << std::endl;
			assert(false);
			return;
		}

		BasicBlock* tBb = nullptr;
		Function* tFnc = nullptr;
		getOrCreateTarget(start, true, tBb, tFnc, nullptr);
		if (tFnc && !tFnc->empty())
		{
			bb = &tFnc->front();
		}
		else
		{
			LOG << "\t\t" << "no bb for fnc -> skip" << std::endl;
			assert(false);
			return;
		}
	}
	assert(bb && bb->getTerminator());
	IRBuilder<> irb(bb->getTerminator());

	Address addr = start;
	Address oldAddr = addr;
	bool bbEnd = false;
	do
	{
		LOG << "\t\t\t" << "translating = " << addr << std::endl;

		oldAddr = addr;
		auto res = _c2l->translateOne(bytes.first, bytes.second, addr, irb);
		if (res.failed() || res.llvmInsn == nullptr)
		{
			if (auto* bb = getBasicBlockAtAddress(addr))
			{
				if (bb->getParent() == irb.GetInsertBlock()->getParent())
				{
					auto* br = irb.CreateBr(bb);
					assert(br->getNextNode() == br->getParent()->getTerminator());
					br->getNextNode()->eraseFromParent();
					LOG << "\t\t" << "translation ended -> reached BB @ "
							<< addr << std::endl;
				}
			}
			else
			{
				LOG << "\t\t" << "translation failed" << std::endl;
			}
			break;
		}

		_llvm2capstone->emplace(res.llvmInsn, res.capstoneInsn);
		bbEnd = getJumpTargetsFromInstruction(oldAddr, res);
	}
	while (!bbEnd);

	auto end = addr > start ? Address(addr-1) : start;
	_ranges.remove(start, end);
	LOG << "\t\tdecoded range = " << AddressRange(start, end) << std::endl;
}

/**
 * Check if the given jump targets and bytes can/should be decoded.
 * \return The number of bytes to skip from decoding. If zero, then dry run was
 *         ok and decoding of this chunk can proceed. If non-zero, remove the
 *         number of bytes from ranges to decode.
 */
std::size_t Decoder::decodeJumpTargetDryRun(
		const JumpTarget& jt,
		std::pair<const std::uint8_t*, std::uint64_t> bytes)
{
	// Architecture-specific dry runs.
	//
	if (_config->getConfig().architecture.isX86())
	{
		return decodeJumpTargetDryRun_x86(jt, bytes);
	}
	else if (_config->getConfig().architecture.isArm())
	{
		return decodeJumpTargetDryRun_arm(jt, bytes);
	}
	else
	{
		assert(false);
	}

	// Common dry run.
	//
	return false;
}

/**
 * @return @c True if this instruction ends basic block, @c false otherwise.
 */
bool Decoder::getJumpTargetsFromInstruction(
		utils::Address addr,
		capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr)
{
	auto nextAddr = addr + tr.size;
	CallInst* pCall = tr.branchCall;

	BasicBlock* tBb = nullptr;
	Function* tFnc = nullptr;

	// Function call -> insert target (if computed).
	//
	if (_c2l->isCallFunctionCall(pCall))
	{
		if (auto t = getJumpTarget(addr, pCall, pCall->getArgOperand(0)))
		{
			getOrCreateTarget(t, true, tBb, tFnc, pCall);
			assert(tFnc && tBb == nullptr);
			transformToCall(pCall, tFnc);

			_jumpTargets.push(
					t,
					JumpTarget::eType::CONTROL_FLOW_CALL_TARGET,
					_currentMode,
					addr);
			LOG << "\t\t" << "call @ " << addr << " -> " << t << std::endl;
		}
	}
	// Return -> break flow, do not try to compute target.
	//
	else if (_c2l->isReturnFunctionCall(pCall))
	{
		transformToReturn(pCall);
		return true;
	}
	// Unconditional branch -> insert target (if computed).
	//
	else if (_c2l->isBranchFunctionCall(pCall))
	{
		if (auto t = getJumpTarget(addr, pCall, pCall->getArgOperand(0)))
		{
			getOrCreateTarget(t, false, tBb, tFnc, pCall);
			if (tBb)
			{
				transformToBranch(pCall, tBb);
			}
			else if (tFnc)
			{
				transformToCall(pCall, tFnc);
			}

			_jumpTargets.push(
					t,
					JumpTarget::eType::CONTROL_FLOW_BR_TRUE,
					_currentMode,
					addr);
			LOG << "\t\t" << "br @ " << addr << " -> "	<< t << std::endl;
		}

		return true;
	}
	// Conditional branch -> insert target (if computed), and next (flow
	// may or may not jump/continue after).
	//
	else if (_c2l->isCondBranchFunctionCall(pCall))
	{
		if (auto t = getJumpTarget(addr, pCall, pCall->getArgOperand(1)))
		{
			getOrCreateTarget(t, false, tBb, tFnc, pCall);

			BasicBlock* tBbN = nullptr;
			Function* tFncN = nullptr;
			getOrCreateTarget(nextAddr, false, tBbN, tFncN, pCall);

			if (tBb && tBbN
					&& tBb->getParent() == tBbN->getParent()
					&& tBb->getParent() == pCall->getFunction())
			{
				transformToCondBranch(pCall, pCall->getOperand(0), tBb, tBbN);
			}
			else if (tFnc && tBbN)
			{
				transformToCondCall(pCall, pCall->getOperand(0), tFnc, tBbN);
			}
			else
			{
				// TODO: deal with this
				assert(false);
			}

			_jumpTargets.push(
					t,
					JumpTarget::eType::CONTROL_FLOW_BR_TRUE,
					_currentMode,
					addr);
			LOG << "\t\t" << "cond br @ " << addr << " -> (true) "
					<< t << std::endl;

			_jumpTargets.push(
					nextAddr,
					JumpTarget::eType::CONTROL_FLOW_BR_FALSE,
					_currentMode,
					addr);
			LOG << "\t\t" << "cond br @ " << addr << " -> (false) "
					<< nextAddr << std::endl;
		}

		return true;
	}

	return false;
}

utils::Address Decoder::getJumpTarget(
		utils::Address addr,
		llvm::CallInst* branchCall,
		llvm::Value* val)
{
	static ReachingDefinitionsAnalysis RDA;
	SymbolicTree st(RDA, val);
	st.simplifyNode(_config);

	if (auto* ci = dyn_cast<ConstantInt>(st.value))
	{
		return ci->getZExtValue();
	}

	if (isa<LoadInst>(st.value)
			&& st.ops.size() == 1
			&& isa<ConstantInt>(st.ops[0].value))
	{
		auto* ci = dyn_cast<ConstantInt>(st.ops[0].value);
		Address addr = ci->getZExtValue();
		if (_imports.count(addr))
		{
			return addr;
		}
		else if (auto* ci = _image->getConstantDefault(addr))
		{
			return ci->getZExtValue();
		}
	}

	// Try to recognize switch pattern.
	// getJumpTargetSwitch() doesn't return target to the caller, it takes care
	// of everything - pseudo to switch transform, jump target creation, ...
	// We just need to return from this function if it succeeds.
	//
	if (getJumpTargetSwitch(addr, branchCall, val, st))
	{
		return Address::getUndef;
	}

	return Address::getUndef;
}

/**
 * \return \c True if switch recognized, \c false otherwise.
 *
 * TODO:
 * - check that all labels can be created before creating them? what if some
 *   creation fails?
 * - remove jump table range from ranges to decode.
 * - store jump table starts for all switches, so when we resolve them at the
 *   end, end switch size was not determined, we can recognize one switch
 *   used labels from subsequent switch table.
 * - use SymbolicTree.
 * - implement jump table size finding.
 */
bool Decoder::getJumpTargetSwitch(
		utils::Address addr,
		llvm::CallInst* branchCall,
		llvm::Value* val,
		SymbolicTree& st)
{
	auto* l = dyn_cast<LoadInst>(val);
	if (l == nullptr)
	{
		return false;
	}

	auto* ptr = skipCasts(l->getPointerOperand());

	ConstantInt* tableAddr = nullptr;
	ConstantInt* itemSz = nullptr;
	Instruction* idxLoad = nullptr;

	if (!match(
			ptr,
			m_Add(
					m_ConstantInt(tableAddr),
					m_Mul(
							m_Instruction(idxLoad),
							m_ConstantInt(itemSz)))))
	{
		return false;
	}

	std::vector<Address> cases;
	Address tableItemAddr = tableAddr->getZExtValue();
	while (true)
	{
		auto* ci = _image->getImage()->isPointer(tableItemAddr)
				? _image->getConstantDefault(tableItemAddr)
				: nullptr;
		if (ci == nullptr)
		{
			break;
		}

		Address item = ci->getZExtValue();
		tableItemAddr += 4;

		cases.push_back(item);
	}

	Address falseAddr;
	Address trueAddr;
	Address defAddr;

	// One addr is this JT, second is already in worlist -> this is
	// true (processed after false), second is false -> cond br on
	// success jumps to this -> second is default label.
	//
	auto* thisBb = branchCall->getParent();
	Address thisBbAddr = getBasicBlockAddress(thisBb);
	for (auto* p : predecessors(thisBb))
	{
		auto* br = dyn_cast<BranchInst>(p->getTerminator());
		if (br && br->isConditional())
		{
			falseAddr = getBasicBlockAddress(br->getSuccessor(1));
			trueAddr = getBasicBlockAddress(br->getSuccessor(0));

			if (thisBbAddr == falseAddr)
			{
				defAddr = trueAddr;
			}
			else if (thisBbAddr == trueAddr)
			{
				defAddr = falseAddr;
			}

			break;
		}
	}

	if (cases.empty() || defAddr.isUndefined())
	{
		return false;
	}

	std::vector<BasicBlock*> casesBbs;
	for (auto c : cases)
	{
		BasicBlock* tBb = nullptr;
		Function* tFnc = nullptr;
		getOrCreateTarget(c, false, tBb, tFnc, branchCall);
		if (tBb && tBb->getParent() == branchCall->getFunction())
		{
			casesBbs.push_back(tBb);
		}
		else
		{
			assert(false);
			return false;
		}
	}

	Function* tFnc = nullptr;
	BasicBlock* defBb = nullptr;
	getOrCreateTarget(defAddr, false, defBb, tFnc, branchCall);
	if (defBb == nullptr
			|| defBb->getParent() != branchCall->getFunction())
	{
		assert(false);
		return false;
	}

	transformToSwitch(branchCall, idxLoad, defBb, casesBbs);

	for (auto c : cases)
	{
		_jumpTargets.push(
				c,
				JumpTarget::eType::CONTROL_FLOW_SWITCH_CASE,
				_currentMode,
				addr);
		LOG << "\t\t" << "switch -> (case) " << c << std::endl;
	}

	_jumpTargets.push(
			defAddr,
			JumpTarget::eType::CONTROL_FLOW_SWITCH_CASE,
			_currentMode,
			addr);
	LOG << "\t\t" << "switch -> (default) " << defAddr << std::endl;
	return true;
}

void Decoder::getOrCreateTarget(
		utils::Address addr,
		bool isCall,
		llvm::BasicBlock*& tBb,
		llvm::Function*& tFnc,
		llvm::Instruction* fromI) // = nullptr
{
	tBb = nullptr;
	tFnc = nullptr;

	if (isCall)
	{
		if (auto* f = getFunctionAtAddress(addr))
		{
			tFnc = f;
		}
		else
		{
			tFnc = _splitFunctionOn(addr);
		}
	}
	else if (fromI == nullptr)
	{
		if (auto* bb = getBasicBlockAtAddress(addr))
		{
			tBb = bb;
		}
		else if (auto ai = AsmInstruction(_module, addr))
		{
			tBb = ai.makeStart();
			tBb->setName(names::generateBasicBlockName(ai.getAddress()));
			addBasicBlock(addr, tBb);
		}
		// Function without BBs (e.g. import declarations).
		else if (auto* targetFnc = getFunctionAtAddress(addr))
		{
			tFnc = targetFnc;
		}
		else if (auto* bb = getBasicBlockBeforeAddress(addr))
		{
			tBb = createBasicBlock(addr, bb->getParent(), bb);
		}
		else
		{
			auto* newFnc = createFunction(addr);
			tBb = &newFnc->front();
		}
	}
	else
	{
		auto* fromFnc = fromI->getFunction();

		getOrCreateTarget(addr, false, tBb, tFnc);

		if (tBb && tBb->getParent() != fromFnc)
		{
			tBb = nullptr;
			tFnc = _splitFunctionOn(addr);
		}
	}
}

void Decoder::removePseudoCalls()
{
	for (Function& f : _module->functions())
	for (BasicBlock& bb : f)
	for (auto it = bb.begin(), e = bb.end(); it != e; )
	{
		CallInst* call = dyn_cast<CallInst>(&(*it));
		++it;

		if (call &&
				(_c2l->isCallFunctionCall(call)
				|| _c2l->isBranchFunctionCall(call)
				|| _c2l->isCondBranchFunctionCall(call)
				|| _c2l->isReturnFunctionCall(call)))
		{
			// Remove operand of return - it would create stack store, that
			// would screw up the param/return analysis.
			// Similar thing is done in other place for x86 calls.
			// TODO: Better implementation - remove all instructions that became
			// unused once pseudo call is removed -> make some special general
			// method for this.
			//
			Instruction* op = nullptr;
			if (_c2l->isReturnFunctionCall(call)
					&& call->getNumOperands() >= 1)
			{
				if (auto* i = dyn_cast<Instruction>(call->getOperand(0)))
				{
					op = i;
				}
			}

			call->eraseFromParent();
			if (op)
			{
				op->eraseFromParent();
			}
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
