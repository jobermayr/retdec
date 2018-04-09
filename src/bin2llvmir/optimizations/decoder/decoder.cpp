/**
* @file src/bin2llvmir/optimizations/decoder/decoder.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <json/json.h>

#include <llvm/IR/Dominators.h>
#include <llvm/IR/PatternMatch.h>
//#include <llvm/Analysis/PostDominators.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
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
	splitOnTerminatingCalls();

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
		LOG << "\t\t\t translating = " << addr << std::endl;

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
					LOG << "\t\ttranslation ended -> reached BB @ " << addr
							<< std::endl;
				}
				else
				{
					// TODO: ???
				}
			}
			else
			{
				LOG << "\t\ttranslation failed" << std::endl;
			}
			break;
		}

		_llvm2capstone->emplace(res.llvmInsn, res.capstoneInsn);
		bbEnd = getJumpTargetsFromInstruction(oldAddr, res);
	}
	while (!bbEnd);

	auto end = addr > start ? Address(addr-1) : start;
	AddressRange decRange(start, end);
	_ranges.remove(decRange);
	LOG << "\t\tdecoded range = " << decRange << std::endl;
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
	cs_mode m = _currentMode;
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
					m,
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
					m,
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
					m,
					addr);
			LOG << "\t\t" << "cond br @ " << addr << " -> (true) "
					<< t << std::endl;

			_jumpTargets.push(
					nextAddr,
					JumpTarget::eType::CONTROL_FLOW_BR_FALSE,
					m,
					addr);
			LOG << "\t\t" << "cond br @ " << addr << " -> (false) "
					<< nextAddr << std::endl;
		}

		return true;
	}

	return false;
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
			tBb->setName("bb_" + ai.getAddress().toHexString());

			_addr2bb[addr] = tBb;
			_bb2addr[tBb] = addr;
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

utils::Address Decoder::getJumpTarget(
		utils::Address addr,
		llvm::CallInst* branchCall,
		llvm::Value* val)
{
	// TODO: In these cases, target will be always the same -> we can remove
	// the pseudo call and never compute it again.
	//
	if (auto* ci = dyn_cast<ConstantInt>(val))
	{
		return ci->getZExtValue();
	}
	else if (isa<LoadInst>(val)
			&& isa<ConstantInt>(skipCasts(cast<LoadInst>(val)->getOperand(0))))
	{
		auto* ci = cast<ConstantInt>(
				skipCasts(cast<LoadInst>(val)->getOperand(0)));
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

	// TODO: In these cases, target may change as more control flow is decoded
	// -> store pseudo calls and recompute (check) them later.
	//

	static ReachingDefinitionsAnalysis RDA;
	SymbolicTree st(RDA, val);
	st.simplifyNode(_config);

	if (auto* ci = dyn_cast<ConstantInt>(st.value))
	{
		return ci->getZExtValue();
	}
	else if (isa<LoadInst>(st.value)
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

	// TODO: Switch - use SYmbolic tree.
	//
	if (auto* l = dyn_cast<LoadInst>(val))
	{
		auto* ptr = skipCasts(l->getPointerOperand());

		ConstantInt* tableAddr = nullptr;
		ConstantInt* itemSz = nullptr;
		Instruction* idxLoad = nullptr;

		if (match(
				ptr,
				m_Add(
						m_ConstantInt(tableAddr),
						m_Mul(
								m_Instruction(idxLoad),
								m_ConstantInt(itemSz)))))
		{
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

			if (!cases.empty() && defAddr.isDefined())
			{
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
						return Address::getUndef;
					}
				}

				Function* tFnc = nullptr;
				BasicBlock* defBb = nullptr;
				getOrCreateTarget(defAddr, false, defBb, tFnc, branchCall);
				if (defBb == nullptr
						|| defBb->getParent() != branchCall->getFunction())
				{
					assert(false);
					return Address::getUndef;
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
			}

			return Address::getUndef;
		}
	}

	return Address::getUndef;
}

//
//==============================================================================
// Other methods.
//==============================================================================
//

void Decoder::splitOnTerminatingCalls()
{
	LOG << "\n splitOnTerminatingCalls():" << std::endl;

	// Find out all terminating functions.
	//
	LOG << "\tfind all terminating functions:" << std::endl;
	std::set<Instruction*> termCalls;
	std::set<Function*> nonTermFncs;
	auto oldSz = _terminatingFncs.size();
	do
	{
		oldSz = _terminatingFncs.size();

		std::set<Function*> potentialTermFncs;
		for (auto* f : _terminatingFncs)
		{
			for (auto* u : f->users())
			{
				if (auto* call = dyn_cast<CallInst>(u))
				{
					termCalls.insert(call);
					if (_terminatingFncs.count(call->getFunction()) == 0
							&& nonTermFncs.count(call->getFunction()) == 0)
					{
						potentialTermFncs.insert(call->getFunction());
					}
				}
			}
		}

		for (auto* f : potentialTermFncs)
		{
			LOG << "\t\tpotential term @ " << f->getName().str() << std::endl;

			std::queue<BasicBlock*> bbWorklist;
			std::set<BasicBlock*> bbSeen;
			bbWorklist.push(&f->front());
			bbSeen.insert(&f->front());

			bool terminating = true;
			while (!bbWorklist.empty())
			{
				auto* workBb = bbWorklist.front();
				bbWorklist.pop();

				bool reachEnd = true;
				for (Instruction& i : *workBb)
				{
					if (termCalls.count(&i))
					{
						reachEnd = false;
						break;
					}
					else if (isa<ReturnInst>(&i))
					{
						terminating = false;
						break;
					}
				}

				if (!terminating)
				{
					break;
				}
				if (reachEnd)
				{
					for (succ_iterator s = succ_begin(workBb), e = succ_end(workBb); s != e; ++s)
					{
						if (bbSeen.count(*s) == 0)
						{
							bbWorklist.push(*s);
							bbSeen.insert(*s);
						}
					}
				}
			}

			if (terminating)
			{
				LOG << "\t\t\t-> IS terminating" << std::endl;
				_terminatingFncs.insert(f);
			}
			else
			{
				LOG << "\t\t\t-> IS NOT terminating" << std::endl;
				nonTermFncs.insert(f);
			}
		}
	} while (oldSz != _terminatingFncs.size());

	// Split Bbs after terminating calls.
	//
	LOG << "\tsplit BBs after terminating calls:" << std::endl;
	for (auto* call : termCalls)
	{
		auto* f = call->getFunction();
		auto* bb = call->getParent();
		AsmInstruction callAi(call);
		AsmInstruction nextAi = callAi.getNext();

		if (callAi.isInvalid()
				|| nextAi.isInvalid())
		{
			continue;
		}

		if (callAi.getBasicBlock() != nextAi.getBasicBlock())
		{
			auto* term = bb->getTerminator();
			ReturnInst::Create(
					call->getModule()->getContext(),
					llvm::UndefValue::get(f->getReturnType()),
					term);
			term->eraseFromParent();
			LOG << "\t\tbreak flow @ " << nextAi.getAddress() << std::endl;
			continue;
		}

		auto* newBb = bb->splitBasicBlock(nextAi.getLlvmToAsmInstruction());
		auto* term = bb->getTerminator();
		ReturnInst::Create(
				call->getModule()->getContext(),
				UndefValue::get(f->getReturnType()),
				term);
		term->eraseFromParent();

		LOG << "\t\tsplit @ " << nextAi.getAddress() << std::endl;

		AsmInstruction lastNop;
		AsmInstruction ai(newBb);
		while (ai.isValid() && ai.getBasicBlock() == newBb)
		{
			if (capstone_utils::isNopInstruction(
					_config->getConfig().architecture,
					ai.getCapstoneInsn()))
			{
				lastNop = ai;
				ai = ai.getNext();
			}
			else
			{
				break;
			}
		}

		if (lastNop.isValid())
		{
			AsmInstruction lastInNewBb(newBb->getTerminator());
			if (lastNop == lastInNewBb)
			{
				LOG << "\t\t\tremove entire BB of NOPs @ "
						<< nextAi.getAddress() << std::endl;

				newBb->eraseFromParent();
				newBb = nullptr;
			}
			else
			{
				LOG << "\t\t\tsplit @ " << lastNop.getNext().getAddress()
						<< std::endl;
				LOG << "\t\t\tremove NOPs @ " << nextAi.getAddress()
						<< std::endl;

				auto* tmpBb = newBb;
				newBb = tmpBb->splitBasicBlock(lastNop.getNext().getLlvmToAsmInstruction());
				tmpBb->eraseFromParent();
			}
		}

		if (newBb)
		{
			Address addr = AsmInstruction::getInstructionAddress(&newBb->front());
			newBb->setName("bb_" + addr.toHexString());
			_addr2bb[addr] = newBb;
			_bb2addr[newBb] = addr;
		}
	}

	// Split functions after terminating calls.
	//
	LOG << "\tsplit functions after terminating calls:" << std::endl;
	for (auto* call : termCalls)
	{
		auto* f = call->getFunction();
		auto* b = call->getParent();
		auto* nextBb = b->getNextNode();
		if (nextBb == nullptr)
		{
			continue;
		}

		std::set<BasicBlock*> before;

		bool split = true;
		bool after = false;
		for (BasicBlock& bb : *f)
		{
			if (after)
			{
				for (auto* p : predecessors(&bb))
				{
					if (before.count(p))
					{
						split = false;
						break;
					}
				}

				if (!split)
				{
					break;
				}

				for (auto* s : successors(&bb))
				{
					if (before.count(s))
					{
						if (&f->front() != s)
						{
							split = false;
							break;
						}
					}
				}
			}
			else if (&bb == call->getParent())
			{
				after = true;
			}
			else
			{
				before.insert(&bb);
			}
		}

		if (split)
		{
			Address addr = getBasicBlockAddress(nextBb);
			assert(addr.isDefined());

			_splitFunctionOn(addr);

			LOG << "\t\tsplit fnc @ " << addr << std::endl;
		}
	}
}

llvm::Function* Decoder::_splitFunctionOn(
		utils::Address addr,
		const std::string& fncName)
{
	std::string name = fncName.empty()
			? "function_" + addr.toHexString()
			: fncName;

	if (auto* bb = getBasicBlockAtAddress(addr))
	{
		return _splitFunctionOn(addr, bb, name);
	}
	else if (auto ai = AsmInstruction(_module, addr))
	{
		auto* oldBb = ai.getBasicBlock();
		auto* newBb = ai.makeStart();

		ReturnInst::Create(
				oldBb->getModule()->getContext(),
				UndefValue::get(oldBb->getParent()->getReturnType()),
				oldBb->getTerminator());
		oldBb->getTerminator()->eraseFromParent();

		_addr2bb[addr] = newBb;
		_bb2addr[newBb] = addr;
		newBb->setName("bb_" + addr.toHexString());

		return _splitFunctionOn(addr, newBb, name);
	}
	else if (auto* before = getBasicBlockBeforeAddress(addr))
	{
		auto* newBb = createBasicBlock(addr, before->getParent(), before);

		_addr2bb[addr] = newBb;
		_bb2addr[newBb] = addr;

		return _splitFunctionOn(addr, newBb, name);
	}
	else
	{
		return createFunction(addr);
	}
}

llvm::Function* Decoder::_splitFunctionOn(
		utils::Address addr,
		llvm::BasicBlock* bb,
		const std::string& fncName)
{
	if (bb->getPrevNode() == nullptr)
	{
		return bb->getParent();
	}

	std::string name = fncName.empty()
			? "function_" + addr.toHexString()
			: fncName;

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

llvm::CallInst* Decoder::transformToCall(
		llvm::CallInst* pseudo,
		llvm::Function* callee)
{
	if (callee == nullptr)
	{
		return nullptr;
	}

	auto* c = CallInst::Create(callee);
	c->insertAfter(pseudo);

	if (_config->getConfig().architecture.isX86())
	{
		eraseReturnAddrStoreInCall_x86(c);
		if (auto* eax = _module->getNamedGlobal("eax"))
		{
			auto* s = new StoreInst(c, eax);
			s->insertAfter(c);
		}
	}

	return c;
}

llvm::CallInst* Decoder::transformToCondCall(
		llvm::CallInst* pseudo,
		llvm::Value* cond,
		llvm::Function* callee,
		llvm::BasicBlock* falseBb)
{
	if (callee == nullptr || falseBb == nullptr)
	{
		return nullptr;
	}

	auto* oldBb = pseudo->getParent();
	auto* newBb = oldBb->splitBasicBlock(pseudo);

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
	if (branchee == nullptr)
	{
		return nullptr;
	}

	auto* term = pseudo->getParent()->getTerminator();
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

} // namespace bin2llvmir
} // namespace retdec
