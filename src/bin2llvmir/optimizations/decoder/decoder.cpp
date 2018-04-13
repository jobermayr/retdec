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

dumpModuleToFile(_module, _config->getOutputDirectory());

	resolvePseudoCalls();
	patternsRecognize();
	finalizePseudoCalls();

dumpControFlowToJson(_module, _config->getOutputDirectory());
dumpModuleToFile(_module, _config->getOutputDirectory());

	initConfigFunction();

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
		// Instructions on some architectures are aligned.
		auto start = _ranges.primaryFront().getStart();
		if (_config->isMipsOrPic32()
				|| _config->isArmOrThumb()) // ppc?
		{
			if (auto m = start % 4)
			{
				_ranges.remove(start, start + (4 - m) - 1);
				start = start + (4 - m);
			}
		}

		jt = JumpTarget(
				start,
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

	bool alternative = false;
	auto* range = _ranges.getPrimary(start);
	if (range == nullptr && jt.getType() < JumpTarget::eType::LEFTOVER)
	{
		range = _ranges.getAlternative(start);
		alternative = true;
	}
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

	if (jt.getType() == JumpTarget::eType::LEFTOVER
			|| (alternative
			&& jt.getType() > JumpTarget::eType::CONTROL_FLOW_RETURN_TARGET))
	{
		if (auto skipSz = decodeJumpTargetDryRun(jt, bytes))
		{
			AddressRange sr(start, start+skipSz-1);
			LOG << "\t\t" << "dry run failed -> skip range = " << sr
					<< std::endl;
			_ranges.remove(sr);
			return;
		}
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
		// Function can not be split, use BB. This BB does not have predecessor,
		// which is not ideal, but it might happen.
		//
		else if (tBb)
		{
			bb = tBb;
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
	bool bbEnd = false;
	do
	{
		LOG << "\t\t\t" << "translating = " << addr << std::endl;

		Address oldAddr = addr;
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
		bbEnd |= getJumpTargetsFromInstruction(oldAddr, res, bytes.second);
		bbEnd |= instructionBreaksBasicBlock(oldAddr, res);

		if (_c2l->hasDelaySlotTypical(res.capstoneInsn->id))
		{
			assert(res.branchCall);
			assert(_c2l->getDelaySlot(res.capstoneInsn->id));
			assert(_c2l->getDelaySlot(res.capstoneInsn->id) == 1);

			auto* oldIp = res.branchCall->getParent()->getTerminator();
			irb.SetInsertPoint(res.branchCall);
			std::size_t sz = _c2l->getDelaySlot(res.capstoneInsn->id);
			for (std::size_t i = 0; i < sz; ++i)
			{
				auto res = _c2l->translateOne(bytes.first, bytes.second, addr, irb);
				if (res.failed() || res.llvmInsn == nullptr)
				{
					break;
				}
				_llvm2capstone->emplace(res.llvmInsn, res.capstoneInsn);
			}
			irb.SetInsertPoint(oldIp);
		}
		else if (_c2l->hasDelaySlotLikely(res.capstoneInsn->id))
		{
			assert(res.branchCall);
			assert(_c2l->getDelaySlot(res.capstoneInsn->id));
			assert(_c2l->getDelaySlot(res.capstoneInsn->id) == 1);

			assert(isa<BranchInst>(res.branchCall->getNextNode()));
			assert(cast<BranchInst>(res.branchCall->getNextNode())->isConditional());

			auto* br = cast<BranchInst>(res.branchCall->getNextNode());
			if (br && br->isConditional())
			{
				auto* nextBb = br->getParent()->getNextNode();
				auto* newBb = BasicBlock::Create(
						_module->getContext(),
						"",
						br->getFunction(),
						nextBb);

				auto* target = br->getSuccessor(0);
				br->setSuccessor(0, newBb);
				auto* newTerm = BranchInst::Create(target, newBb);
				irb.SetInsertPoint(newTerm);

				std::size_t sz = _c2l->getDelaySlot(res.capstoneInsn->id);
				for (std::size_t i = 0; i < sz; ++i)
				{
					auto res = _c2l->translateOne(bytes.first, bytes.second, addr, irb);
					if (res.failed() || res.llvmInsn == nullptr)
					{
						break;
					}
					_llvm2capstone->emplace(res.llvmInsn, res.capstoneInsn);
				}

				_likelyBb2Target.emplace(newBb, target);
			}
		}
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
	else if (_config->isMipsOrPic32())
	{
		return decodeJumpTargetDryRun_mips(jt, bytes);
	}
	else
	{
		assert(false);
	}

	// Common dry run.
	//
	return false;
}

bool Decoder::instructionBreaksBasicBlock(
		utils::Address addr,
		capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr)
{
	// On x86 halt may get generated to end the entry point function:
	// https://stackoverflow.com/questions/5213466/why-does-gcc-place-a-halt-instruction-in-programs-after-the-call-to-main
	// The check could be stricter - nop follows, all paths to halt, etc.
	//
	if (_config->getConfig().architecture.isX86()
			&& tr.llvmInsn->getFunction() == _entryPointFunction
			&& tr.capstoneInsn->id == X86_INS_HLT)
	{
		return true;
	}

	return false;
}

/**
 * @return @c True if this instruction ends basic block, @c false otherwise.
 */
bool Decoder::getJumpTargetsFromInstruction(
		utils::Address addr,
		capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr,
		uint64_t& rangeSize)
{
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

			// The created function might be in range that we are currently
			// decoding -> if so, trim range size.
			auto nextAddr = addr + tr.size;
			if (nextAddr < t && t < nextAddr + rangeSize)
			{
				rangeSize = t - nextAddr;
			}

			if (_terminatingFncs.count(tFnc))
			{
				return true;
			}
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

			// TODO: if target was from load of import addr, do not add it,
			// add everywhere, make this somehow better.
			if (_imports.count(t) == 0)
			{
				_jumpTargets.push(
						t,
						JumpTarget::eType::CONTROL_FLOW_BR_TRUE,
						_currentMode,
						addr);
			}
			LOG << "\t\t" << "br @ " << addr << " -> "	<< t << std::endl;
		}

		return true;
	}
	// Conditional branch -> insert target (if computed), and next (flow
	// may or may not jump/continue after).
	//
	else if (_c2l->isCondBranchFunctionCall(pCall))
	{
		auto nextAddr = addr + tr.size;
		// Right now, delay slots are only in architectures with fixed
		// instruction size (more specifically, only in MIPS).
		// Therefore, we can multiply current instruction size with number of
		// instructions in the delay slot to get its size.
		// If this changes, we will have to modify this -> create nextAddr
		// target only after delay slot instructions are decoded and we know
		// their sizes.
		//
		nextAddr += _c2l->getDelaySlot(tr.capstoneInsn->id) * tr.size;

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

			// There is no need to break BB and its decoding if target was not
			// found.
			//
			_jumpTargets.push(
					nextAddr,
					JumpTarget::eType::CONTROL_FLOW_BR_FALSE,
					_currentMode,
					addr);
			LOG << "\t\t" << "cond br @ " << addr << " -> (false) "
					<< nextAddr << std::endl;

			return true;
		}
	}
	// Analyze ordinary (not control flow) instruction.
	// TODO: maybe move to separate function.
	//
	else
	{
		AsmInstruction ai(tr.llvmInsn);
		for (auto& i : ai)
		{
			// Skip ranges from which there are loads.
			// Mostly for ARM where there are data references after functions
			// in .text section.
			// We do not use Symbolic tree here, since control flow is not fully
			// reconstructed - matching only constants is safe and should be
			// enough for most cases.
			//
			auto* l = dyn_cast<LoadInst>(&i);
			if (l && isa<ConstantInt>(skipCasts(l->getPointerOperand())))
			{
				auto* ci = dyn_cast<ConstantInt>(skipCasts(l->getPointerOperand()));
				Address t(ci->getZExtValue());
				auto sz = getTypeByteSizeInBinary(_module, l->getType());
				AddressRange r(t, t+sz-1);
				_ranges.remove(r);

				LOG << "\t\t\t\t" << "skip " << r << std::endl;
			}
		}
	}

	return false;
}

utils::Address Decoder::getJumpTarget(
		utils::Address addr,
		llvm::CallInst* branchCall,
		llvm::Value* val)
{
	SymbolicTree st(_RDA, val, nullptr, 16);
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
 */
bool Decoder::getJumpTargetSwitch(
		utils::Address addr,
		llvm::CallInst* branchCall,
		llvm::Value* val,
		SymbolicTree& st)
{
	unsigned archByteSz =  _config->getConfig().architecture.getByteSize();

	// Pattern:
	//>|   %55 = load i32, i32* %54
	//		>|   %53 = add i32 Addr, %52
	//				>|   %52 = mul i32 %51, 4
	//						>| idx
	//						>| i32 4
	//				>| i32 tableAddr
	if (!(isa<LoadInst>(st.value) // load
			&& st.ops.size() == 1
			&& isa<AddOperator>(st.ops[0].value) // add
			&& st.ops[0].ops.size() == 2
			&& (isa<MulOperator>(st.ops[0].ops[0].value) // mul
					|| isa<ShlOperator>(st.ops[0].ops[0].value)) // shl
			&& st.ops[0].ops[0].ops.size() == 2
			&& isa<ConstantInt>(st.ops[0].ops[0].ops[1].value)
			&& isa<ConstantInt>(st.ops[0].ops[1].value))) // table address
	{
		return false;
	}

	bool usesMul = isa<MulOperator>(st.ops[0].ops[0].value);
	bool usesShl = isa<ShlOperator>(st.ops[0].ops[0].value);
	auto* mulShlCi = cast<ConstantInt>(st.ops[0].ops[0].ops[1].value);
	if (!((usesMul && mulShlCi->getZExtValue() == archByteSz)
			|| (usesShl && (1 << mulShlCi->getZExtValue()) == archByteSz)))
	{
		return false;
	}

	Address tableAddr = cast<ConstantInt>(st.ops[0].ops[1].value)->getZExtValue();
	Value* idx = cast<Instruction>(st.ops[0].ops[0].value)->getOperand(0);

	LOG << "\t\t" << "switch @ " << addr << std::endl;
	LOG << "\t\t\t" << "table addr @ " << tableAddr << std::endl;

	// Default target.
	//
	Address defAddr;
	BranchInst* brToSwitch = nullptr;
	auto* thisBb = branchCall->getParent();
	Address thisBbAddr = getBasicBlockAddress(thisBb);
	for (auto* p : predecessors(thisBb))
	{
		auto* br = dyn_cast<BranchInst>(p->getTerminator());
		if (br && br->isConditional())
		{
			brToSwitch = br;

			Address falseAddr = getBasicBlockAddress(br->getSuccessor(1));
			Address trueAddr = getBasicBlockAddress(br->getSuccessor(0));

			// Branching over this BB -> true branching to default case.
			if (thisBbAddr == falseAddr)
			{
				LOG << "\t\t\t\t" << "default: branching over" << std::endl;
				defAddr = trueAddr;
			}
			// Branching to this BB -> false branching to default case.
			else if (thisBbAddr == trueAddr)
			{
				LOG << "\t\t\t\t" << "default: branching to" << std::endl;
				defAddr = falseAddr;
			}

			break;
		}
	}
	if (defAddr.isUndefined() || brToSwitch == nullptr)
	{
		LOG << "\t\t\t" << "no default target -> skip" << std::endl;
		// TODO: detected labels still should become jump targets.
		// problem, we don't know the jump target type -> they can be functions,
		// not just branch targets.
		// e.g. 04023A3 @ call ds:___CTOR_LIST__[ebx*4]
		return false;
	}
	else
	{
		LOG << "\t\t\t" << "default label @ " << defAddr << std::endl;
	}

	// Jump table size.
	// maybe we could check that compared value is indeed index value.
	//
	unsigned tableSize = 0;
	SymbolicTree stCond(_RDA, brToSwitch->getCondition());
	stCond.simplifyNode(_config);
	auto levelOrd = stCond.getLevelOrder();
	for (SymbolicTree* n : levelOrd)
	{
		// x86:
		//>|   %331 = or i1 %329, %330
		//		>|   %317 = icmp ult i8 %312, 90
		//				>|   %296 = sub i32 %295, 32
		//				>| i8 90
		//		>|   %322 = icmp eq i8 %313, 0
		//				>|   %313 = sub i8 %312, 90
		//						>|   %312 = trunc i32 %311 to i8
		//						>| i8 90
		//				>| i8 0
		if (isa<BinaryOperator>(n->value)
				&& cast<BinaryOperator>(n->value)->getOpcode()
						== Instruction::Or
				&& n->ops.size() == 2
				&& isa<ICmpInst>(n->ops[0].value)
				&& cast<ICmpInst>(n->ops[0].value)->getPredicate()
						== ICmpInst::ICMP_ULT
				&& n->ops[0].ops.size() == 2
				&& isa<ConstantInt>(n->ops[0].ops[1].value)
				&& isa<ICmpInst>(n->ops[1].value)
				&& cast<ICmpInst>(n->ops[1].value)->getPredicate()
						== ICmpInst::ICMP_EQ
				&& n->ops[1].ops.size() == 2
				&& isa<ConstantInt>(n->ops[1].ops[1].value)
				&& cast<ConstantInt>(n->ops[1].ops[1].value)->isZero())
		{
			auto* ci = cast<ConstantInt>(n->ops[0].ops[1].value);
			tableSize = ci->getZExtValue() + 1;
			LOG << "\t\t\t" << "table size (1) = " << tableSize << std::endl;
			break;
		}
		// mips:
		//>|   %319 = icmp ne i32 %318, 0
		//		>|   %316 = icmp ult i32 %315, 121
		//				>|   %314 = and i32 %313, 255
		//				>| i32 121
		//		>| i32 0
		else if (isa<ICmpInst>(n->value)
				&& cast<ICmpInst>(n->value)->getPredicate()
						== ICmpInst::ICMP_NE
				&& isa<ICmpInst>(n->ops[0].value)
				&& cast<ICmpInst>(n->ops[0].value)->getPredicate()
						== ICmpInst::ICMP_ULT
				&& isa<ConstantInt>(n->ops[0].ops[1].value)
				&& !cast<ConstantInt>(n->ops[0].ops[1].value)->isZero()
				&& isa<ConstantInt>(n->ops[1].value)
				&& cast<ConstantInt>(n->ops[1].value)->isZero())
		{
			auto* ci = cast<ConstantInt>(n->ops[0].ops[1].value);
			tableSize = ci->getZExtValue();
			LOG << "\t\t\t" << "table size (2) = " << tableSize << std::endl;
			break;
		}
		// mips:
		//>|   %524 = icmp eq i32 %523, 0
		//		>|   %449 = icmp ult i32 %448, 5
		//				>| i32 3
		//				>| i32 5
		//		>| i32 0
		else if (isa<ICmpInst>(n->value)
				&& cast<ICmpInst>(n->value)->getPredicate()
						== ICmpInst::ICMP_EQ
				&& isa<ICmpInst>(n->ops[0].value)
				&& cast<ICmpInst>(n->ops[0].value)->getPredicate()
						== ICmpInst::ICMP_ULT
				&& isa<ConstantInt>(n->ops[0].ops[1].value)
				&& !cast<ConstantInt>(n->ops[0].ops[1].value)->isZero()
				&& isa<ConstantInt>(n->ops[1].value)
				&& cast<ConstantInt>(n->ops[1].value)->isZero())
		{
			auto* ci = cast<ConstantInt>(n->ops[0].ops[1].value);
			tableSize = ci->getZExtValue();
			LOG << "\t\t\t" << "table size (3) = " << tableSize << std::endl;
			break;
		}
	}

	// Get targets from jump table.
	//
	LOG << "\t\t\t" << "table labels:" << std::endl;
	std::vector<Address> cases;
	Address tableItemAddr = tableAddr;
	Address nextTableAddr;
	auto swTblIt = _switchTableStarts.upper_bound(tableAddr);
	if (swTblIt != _switchTableStarts.end())
	{
		nextTableAddr = swTblIt->first;
	}
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
		LOG << "\t\t\t\t" << item << " @ " << tableItemAddr << std::endl;

		tableItemAddr += archByteSz;
		cases.push_back(item);

		if (tableSize > 0 && cases.size() == tableSize)
		{
			break;
		}
		if (nextTableAddr.isUndefined() && tableItemAddr >= nextTableAddr)
		{
			break;
		}
	}
	if (cases.empty())
	{
		LOG << "\t\t\t" << "no targets @ " << tableAddr << " -> skip"
				<< std::endl;
		return false;
	}
	Address tableAddrEnd = tableItemAddr;

	//
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

	auto* sw = transformToSwitch(branchCall, idx, defBb, casesBbs);

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

	_ranges.remove(tableAddr, tableAddrEnd - 1);

	_switchTableStarts[tableAddr].insert(sw);

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
			return;
		}
		else if (auto* f = splitFunctionOn(addr))
		{
			tFnc = f;
			return;
		}
	}

	if (fromI == nullptr)
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
			tFnc = splitFunctionOn(addr);
		}
	}
}

void Decoder::resolvePseudoCalls()
{
	// TODO: fix point algorithm that tries to re-solve all solved and unsolved
	// pseudo calls?
	// - the same result -> ok, nothing
	// - no result -> revert transformation
	// - new result -> new transformation
	// This will not be easy. Can fixpoint even be reached? Reverts, etc. are
	// hard and ugly.

	for (Function& f : *_module)
	for (BasicBlock& b : f)
	for (auto i = b.begin(), e = b.end(); i != e;)
	{
		CallInst* pseudo = dyn_cast<CallInst>(&*i);
		++i;
		if (pseudo == nullptr)
		{
			continue;
		}
		if (!_c2l->isCallFunctionCall(pseudo)
				&& !_c2l->isReturnFunctionCall(pseudo)
				&& !_c2l->isBranchFunctionCall(pseudo)
				&& !_c2l->isCondBranchFunctionCall(pseudo))
		{
			continue;
		}

		Instruction* real = pseudo->getNextNode();
		if (real == nullptr)
		{
			continue;
		}
		++i;

		// TODO: fix calls, maybe we could create the calls for the first time
		// here.
		//
		if (_c2l->isCallFunctionCall(pseudo)
				&& isa<CallInst>(real))
		{
			Address t = getJumpTarget(
					AsmInstruction::getInstructionAddress(real),
					pseudo,
					pseudo->getArgOperand(0));

			if (t.isUndefined())
			{
				++i;
				auto* st = cast<StoreInst>(*real->user_begin());
				st->eraseFromParent();
				real->eraseFromParent();
			}
		}
	}
}

void Decoder::finalizePseudoCalls()
{
	for (auto& f : *_module)
	for (auto& b : f)
	for (auto i = b.begin(), e = b.end(); i != e;)
	{
		CallInst* pseudo = dyn_cast<CallInst>(&*i);
		++i;
		if (pseudo == nullptr)
		{
			continue;
		}
		if (!_c2l->isCallFunctionCall(pseudo)
				&& !_c2l->isReturnFunctionCall(pseudo)
				&& !_c2l->isBranchFunctionCall(pseudo)
				&& !_c2l->isCondBranchFunctionCall(pseudo))
		{
			continue;
		}

		Instruction* it = pseudo->getPrevNode();
		pseudo->eraseFromParent();

		bool mipsFirstAsmInstr = true;
		while (it)
		{
			if (AsmInstruction::isLlvmToAsmInstruction(it))
			{
				if (_config->isMipsOrPic32() && mipsFirstAsmInstr)
				{
					mipsFirstAsmInstr = false;
				}
				else
				{
					break;
				}
			}

			auto* i = it;
			it = it->getPrevNode();

			// Return address store to stack in x86 calls.
			//
			if (_config->getConfig().architecture.isX86()
					&& (_c2l->isCallFunctionCall(pseudo)
							|| _c2l->isReturnFunctionCall(pseudo)))
			if (auto* st = dyn_cast<StoreInst>(i))
			{
				if (_config->isStackPointerRegister(st->getPointerOperand())
						|| isa<ConstantInt>(st->getValueOperand()))
				{
					st->eraseFromParent();
				}
			}

			// Return address store to register in MIPS calls.
			//
			if (_config->isMipsOrPic32() && _c2l->isCallFunctionCall(pseudo))
			if (auto* st = dyn_cast<StoreInst>(i))
			{
				if (_c2l->isRegister(st->getPointerOperand())
						&& st->getPointerOperand()->getName() == "ra")
				{
					st->eraseFromParent();
				}
			}

			if (!i->getType()->isVoidTy() && i->use_empty())
			{
				i->eraseFromParent();
			}
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
