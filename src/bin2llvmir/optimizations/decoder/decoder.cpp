/**
* @file src/bin2llvmir/optimizations/decoder/decoder.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <json/json.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/utils/instruction.h"
#include "retdec/bin2llvmir/utils/type.h"
#include "retdec/llvm-support/utils.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace retdec::capstone2llvmir;
using namespace llvm;
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

bool Decoder::runOnModule(Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_image = FileImageProvider::getFileImage(_module);
	_debug = DebugFormatProvider::getDebugFormat(_module);
	_llvm2capstone = &AsmInstruction::getLlvmToCapstoneInsnMap(_module);
	return runCatcher();
}

bool Decoder::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		FileImage* o,
		DebugFormat* d)
{
	_module = &m;
	_config = c;
	_image = o;
	_debug = d;
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
	initEnvironment();
	initRanges();
	initJumpTargets();

	LOG << std::endl;
	LOG << "Allowed ranges:" << std::endl;
	LOG << _allowedRanges << std::endl;
	LOG << std::endl;
	LOG << "Alternative ranges:" << std::endl;
	LOG << _alternativeRanges << std::endl;
	LOG << "Jump targets:" << std::endl;
	LOG << _jumpTargets << std::endl;
	LOG << std::endl;

	decode();

dumpModuleToFile(_module);
//dumpControFlowToJson_jsoncpp();
dumpControFlowToJsonModule_manual();
exit(1);
	return false;
}

void Decoder::decode()
{
	LOG << "\n doDecoding()" << std::endl;

	JumpTarget jt;
	while (getJumpTarget(jt))
	{
		LOG << "\tprocessing : " << jt << std::endl;
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
	else if (!_allowedRanges.empty())
	{
		jt = JumpTarget(
				_allowedRanges.begin()->getStart(),
				JumpTarget::eType::LEFTOVER,
				CS_MODE_BIG_ENDIAN,
				Address());
		return true;
	}
	return false;
}

void Decoder::decodeJumpTarget(const JumpTarget& jt)
{
	Address start = jt.address;
	Address addr = start;

	if (addr.isUndefined())
	{
		LOG << "\t\tunknown target address -> skipped" << std::endl;
		return;
	}

	auto* range = _allowedRanges.getRange(addr);
	if (range == nullptr)
	{
		if (jt.type == JumpTarget::eType::CONTROL_FLOW_BR_FALSE)
		{
			auto* fromInst = jt.getFromInstruction();
			auto* fromFnc = fromInst->getFunction();
			auto* targetBb = getBasicBlockAtAddress(jt.address);

			if (targetBb && targetBb->getParent() == fromFnc)
			{
				_pseudoWorklist.setTargetBbFalse(
						llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
						targetBb);
				return;
			}
			else
			{
				assert(false);
			}
		}
		else if (jt.type == JumpTarget::eType::CONTROL_FLOW_BR_TRUE)
		{
			auto* fromInst = jt.getFromInstruction();
			auto* fromFnc = fromInst->getFunction();
			auto* targetBb = getBasicBlockAtAddress(jt.address);

			if (targetBb == nullptr)
			{
				auto ai = AsmInstruction(_module, jt.address);
				if (ai.isValid() && ai.getFunction() == fromFnc)
				{
					auto* newBb = ai.makeStart();

					_addr2bb[jt.address] = newBb;
					_bb2addr[newBb] = jt.address;

					_pseudoWorklist.setTargetBbTrue(
							llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
							newBb);
					return;
				}
				else if (ai.isValid())
				{
					std::string n = "function_" + jt.address.toHexString();
					auto* newFnc = splitFunctionOn(ai.getLlvmToAsmInstruction(), n);
					auto* newBb = &newFnc->front();

					_addr2fnc[jt.address] = newFnc;
					_fnc2addr[newFnc] = jt.address;

					_addr2bb[jt.address] = newBb;
					_bb2addr[newBb] = jt.address;

					_pseudoWorklist.setTargetBbTrue(
							llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
							newBb);

				}
				else
				{
					assert(false);
				}
			}
			else if (targetBb->getParent() == fromFnc)
			{
				_pseudoWorklist.setTargetBbTrue(
						llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
						targetBb);
				return;
			}
			// Target is different function (target BB = fnc start) -> change
			// jmp for call.
			//
			else if (&targetBb->getParent()->front() == targetBb)
			{
				_pseudoWorklist.setTargetBbTrue(
						llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
						targetBb);
			}
			else
			{
				assert(false);
			}
		}
		else if (jt.type == JumpTarget::eType::CONTROL_FLOW_CALL_TARGET)
		{
			if (auto* f = getFunctionAtAddress(jt.address))
			{
				_pseudoWorklist.setTargetFunction(
						llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
						f);
				return;
			}
			else if (auto ai = AsmInstruction(_module, jt.address))
			{
				std::string n = "function_" + jt.address.toHexString();
				auto* newFnc = splitFunctionOn(ai.getLlvmToAsmInstruction(), n);
				auto* newBb = &newFnc->front();

				_addr2fnc[jt.address] = newFnc;
				_fnc2addr[newFnc] = jt.address;

				_addr2bb[jt.address] = newBb;
				_bb2addr[newBb] = jt.address;

				_pseudoWorklist.setTargetFunction(
						llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
						newFnc);
			}
			else
			{
				assert(false);
			}
		}

		LOG << "\t\tfound no range -> skipped" << std::endl;
		return;
	}
	else
	{
		LOG << "\t\tfound range = " << *range << std::endl;
	}

	auto bytes = _image->getImage()->getRawSegmentData(addr);
	if (bytes.first == nullptr)
	{
		LOG << "\t\tfound no data -> skipped" << std::endl;
		return;
	}

	auto toRangeEnd = range->getEnd() + 1 - addr;
	bytes.second = toRangeEnd < bytes.second ? toRangeEnd : bytes.second;

	if (auto skipSz = decodeJumpTargetDryRun(jt, bytes))
	{
		AddressRange skipRange(start, start+skipSz-1);
		LOG << "\t\tdry run failed -> skip range = " << skipRange << std::endl;
		_allowedRanges.remove(skipRange);
		return;
	}

	auto irb = getIrBuilder(jt);

	bool bbEnd = false;
	do
	{
		LOG << "\t\t\t translating = " << addr << std::endl;
		auto res = _c2l->translateOne(bytes.first, bytes.second, addr, irb);
		_llvm2capstone->emplace(res.llvmInsn, res.capstoneInsn);
		AsmInstruction ai(res.llvmInsn);
		if (res.failed() || res.llvmInsn == nullptr || ai.isInvalid())
		{
			if (auto* bb = getBasicBlockAtAddress(addr))
			{
				auto* br = irb.CreateBr(bb);
				// Potential return.
				if (br->getParent()->getTerminator() != br)
				{
					br->getParent()->getTerminator()->eraseFromParent();
				}
				LOG << "\t\ttranslation ended -> reached BB @ " << addr
						<< std::endl;
			}
			else
			{
				LOG << "\t\ttranslation failed" << std::endl;
			}
			break;
		}
		bbEnd = getJumpTargetsFromInstruction(ai, res);
	}
	while (!bbEnd);

	auto end = addr > start ? Address(addr-1) : start;
	AddressRange decRange(start, end);
	LOG << "\t\tdecoded range = " << decRange << std::endl;

	_allowedRanges.remove(decRange);
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

	// Common dry run.
	//
	return false;
}

std::size_t Decoder::decodeJumpTargetDryRun_x86(
		const JumpTarget& jt,
		std::pair<const std::uint8_t*, std::uint64_t> bytes)
{
	static csh ce = _c2l->getCapstoneEngine();
	static cs_insn* insn = cs_malloc(ce);

	uint64_t addr = jt.address;
	while (cs_disasm_iter(ce, &bytes.first, &bytes.second, &addr, insn))
	{
		if (_c2l->isReturnInstruction(*insn)
				|| _c2l->isBranchInstruction(*insn))
		{
			return false;
		}
	}

	if (getBasicBlockAtAddress(addr))
	{
		return false;
	}

	return true;
}

llvm::IRBuilder<> Decoder::getIrBuilder(const JumpTarget& jt)
{
	if (_addr2fnc.empty())
	{
		auto* f = createFunction(jt.address, jt.getName());
		return llvm::IRBuilder<>(&f->front().front());
	}
	else if (jt.type == JumpTarget::eType::CONTROL_FLOW_BR_FALSE)
	{
		auto* bb = createBasicBlock(
				jt.address,
				jt.getName(),
				jt.getFromInstruction()->getFunction(),
				jt.getFromInstruction()->getParent());
		_pseudoWorklist.setTargetBbFalse(
				llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
				bb);
		return llvm::IRBuilder<>(bb->getTerminator());
	}
	else if (jt.type == JumpTarget::eType::CONTROL_FLOW_BR_TRUE)
	{
		auto* fromInst = jt.getFromInstruction();
		auto* fromFnc = fromInst->getFunction();
		auto* targetFnc = getFunctionBeforeAddress(jt.address);

		if (targetFnc == nullptr)
		{
			auto* f = createFunction(jt.address, jt.getName());

			_pseudoWorklist.setTargetFunction(
					llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
					f);

			return llvm::IRBuilder<>(&f->front().front());
		}
		else if (targetFnc == fromFnc)
		{
			auto* targetBb = getBasicBlockBeforeAddress(jt.address);
			if (targetBb == nullptr)
			{
				// Should not ne possible - in this function, but before 1. BB.
				assert(false);
			}

			auto* newBb = createBasicBlock(
					jt.address,
					jt.getName(),
					targetFnc,
					targetBb);

			_pseudoWorklist.setTargetBbTrue(
					llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
					newBb);

			return llvm::IRBuilder<>(newBb->getTerminator());
		}
		else
		{
			auto targetFncAddr = getFunctionAddress(targetFnc);
			if (targetFncAddr == jt.address)
			{
				// There is such function, but that means its entry BB was
				// already decoded, something is wrong here.
				assert(false);
			}

			auto* contFnc = getFunctionContainingAddress(jt.address);
			if (contFnc)
			{
				assert(false);
			}
			else
			{
				auto* f = createFunction(jt.address, jt.getName());

				_pseudoWorklist.setTargetFunction(
						llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
						f);

				return llvm::IRBuilder<>(&f->front().front());
			}
		}
	}
	else if (jt.type == JumpTarget::eType::CONTROL_FLOW_CALL_TARGET)
	{
		if (getFunctionAtAddress(jt.address))
		{
			// There is such function, but that means its entry BB was already
			// decoded, something is wrong here.
			assert(false);
		}
		else if (getFunctionContainingAddress(jt.address))
		{
			// TODO: Address inside another function -> split that function.
			assert(false);
		}
		else if (auto* f = createFunction(jt.address, jt.getName()))
		{
			_pseudoWorklist.setTargetFunction(
					llvm::cast<llvm::CallInst>(jt.getFromInstruction()),
					f);

			return llvm::IRBuilder<>(&f->front().front());
		}
	}
	else if (jt.type == JumpTarget::eType::LEFTOVER)
	{
		if (auto* targetFnc = getFunctionContainingAddress(jt.address))
		{
			auto* targetBb = getBasicBlockBeforeAddress(jt.address);
			assert(targetBb);

			auto* newBb = createBasicBlock(
					jt.address,
					jt.getName(),
					targetFnc,
					targetBb);

			return llvm::IRBuilder<>(newBb->getTerminator());
		}
		else
		{
			auto* f = createFunction(jt.address, jt.getName());
			return llvm::IRBuilder<>(&f->front().front());
		}
	}

	assert(false);
}

/**
 * @return @c True if this instruction ends basic block, @c false otherwise.
 */
bool Decoder::getJumpTargetsFromInstruction(
		AsmInstruction& ai,
		capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr)
{
	analyzeInstruction(ai, tr);

	cs_mode m = _currentMode;
	auto addr = ai.getAddress();
	auto nextAddr = addr + tr.size;

	// Function call -> insert target (if computed) and next (call
	// may return).
	//
	if (_c2l->isCallFunctionCall(tr.branchCall))
	{
		if (auto t = getJumpTarget(tr.branchCall->getArgOperand(0)))
		{
			_jumpTargets.push(
					t,
					JumpTarget::eType::CONTROL_FLOW_CALL_TARGET,
					m,
					tr.branchCall);
			LOG << "\t\t" << "call @ " << addr << " -> " << t << std::endl;
		}

		_pseudoWorklist.addPseudoCall(tr.branchCall);

		return false;
	}
	// Return -> insert target (if computed).
	// Next is not inserted, flow does not continue after unconditional
	// branch.
	// Computing target (return address on stack) is hard, so it
	// probably will not be successful, but we try anyway.
	//
	else if (_c2l->isReturnFunctionCall(tr.branchCall))
	{
		if (auto t = getJumpTarget(tr.branchCall->getArgOperand(0)))
		{
			_jumpTargets.push(
					t,
					JumpTarget::eType::CONTROL_FLOW_RETURN_TARGET,
					m,
					tr.branchCall);
			LOG << "\t\t" << "return @ " << addr << " -> " << t << std::endl;
		}

		_pseudoWorklist.addPseudoReturn(tr.branchCall);

		return true;
	}
	// Unconditional branch -> insert target (if computed).
	// Next is not inserted, flow does not continue after unconditional
	// branch.
	else if (_c2l->isBranchFunctionCall(tr.branchCall))
	{
		if (auto t = getJumpTarget(tr.branchCall->getArgOperand(0)))
		{
			_jumpTargets.push(
					t,
					JumpTarget::eType::CONTROL_FLOW_BR_TRUE,
					m,
					tr.branchCall);
			LOG << "\t\t" << "br @ " << addr << " -> "	<< t << std::endl;
		}

		_pseudoWorklist.addPseudoBr(tr.branchCall);

		return true;
	}
	// Conditional branch -> insert target (if computed) and next (flow
	// may or may not jump/continue after).
	//
	else if (_c2l->isCondBranchFunctionCall(tr.branchCall))
	{
		if (auto t = getJumpTarget(tr.branchCall->getArgOperand(1)))
		{
			_jumpTargets.push(
					t,
					JumpTarget::eType::CONTROL_FLOW_BR_TRUE,
					m,
					tr.branchCall);
			LOG << "\t\t" << "cond br @ " << addr << " -> (true) "
					<< t << std::endl;
		}

		_jumpTargets.push(
				nextAddr,
				JumpTarget::eType::CONTROL_FLOW_BR_FALSE,
				m,
				tr.branchCall);
		LOG << "\t\t" << "cond br @ " << addr << " -> (false) "
				<< nextAddr << std::endl;

		_pseudoWorklist.addPseudoCondBr(tr.branchCall);

		return true;
	}

	return false;
}

void Decoder::analyzeInstruction(
		AsmInstruction& ai,
		capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr)
{
	// TODO:
	// - extract jump targets from ordinary instructions.
	// - recognize NOPs
	// - optimize instruction
	// - etc.
}

retdec::utils::Address Decoder::getJumpTarget(llvm::Value* val)
{
	if (auto* ci = dyn_cast<ConstantInt>(val))
	{
		return ci->getZExtValue();
	}
	return Address::getUndef;
}

//
//==============================================================================
// Function helper methods.
//==============================================================================
//

/**
 * \return Start address for function \p f.
 */
retdec::utils::Address Decoder::getFunctionAddress(llvm::Function* f)
{
	auto fIt = _fnc2addr.find(f);
	return fIt != _fnc2addr.end() ? fIt->second : Address();
}

/**
 * \return End address for function \p f.
 * \note End address is one byte beyond the function, i.e. <start, end).
 */
retdec::utils::Address Decoder::getFunctionEndAddress(llvm::Function* f)
{
	if (f == nullptr)
	{
		Address();
	}

	if (f->empty() || f->back().empty())
	{
		return getFunctionAddress(f);
	}

	AsmInstruction ai(&f->back().back());
	return ai.isValid() ? ai.getEndAddress() : Address();
}

/**
 * \return Function exactly at address \p a.
 */
llvm::Function* Decoder::getFunctionAtAddress(retdec::utils::Address a)
{
	auto fIt = _addr2fnc.find(a);
	return fIt != _addr2fnc.end() ? fIt->second : nullptr;
}

/**
 * \return The first function before or at address \p a.
 */
llvm::Function* Decoder::getFunctionBeforeAddress(retdec::utils::Address a)
{
	if (_addr2fnc.empty())
	{
		return nullptr;
	}

	// Iterator to the first element whose key goes after a.
	auto it = _addr2fnc.upper_bound(a);

	// The first function is after a -> no function before a.
	if (it == _addr2fnc.begin())
	{
		return nullptr;
	}
	// No function after a -> the last function before a.
	else if (it == _addr2fnc.end())
	{
		return _addr2fnc.rbegin()->second;
	}
	// Function after a exists -> the one before it is before a.
	else
	{
		--it;
		return it->second;
	}
}

/**
 * \return Function that contains the address \p a. I.e. \p a is between
 * function's start and end address.
 */
llvm::Function* Decoder::getFunctionContainingAddress(retdec::utils::Address a)
{
	if (auto* f = getFunctionBeforeAddress(a))
	{
		Address end = getFunctionEndAddress(f);
		return a.isDefined() && end.isDefined() && a < end ? f : nullptr;
	}
	return nullptr;
}

/**
 * Create function at address \p a with name \p name.
 * \return Created function.
 */
llvm::Function* Decoder::createFunction(
		retdec::utils::Address a,
		const std::string& name)
{
	std::string n = name.empty() ? "function_" + a.toHexString() : name;

	llvm::Function* f = nullptr;
	auto& fl = _module->getFunctionList();

	if (fl.empty())
	{
		f = llvm::Function::Create(
				llvm::FunctionType::get(
						getDefaultType(_module),
						false),
				llvm::GlobalValue::ExternalLinkage,
				n,
				_module);
	}
	else
	{
		f = llvm::Function::Create(
				llvm::FunctionType::get(
						getDefaultType(_module),
						false),
				llvm::GlobalValue::ExternalLinkage,
				n);
	}

	llvm::Function* before = getFunctionBeforeAddress(a);
	if (before)
	{
		fl.insertAfter(before->getIterator(), f);
	}
	else
	{
		fl.insert(fl.begin(), f);
	}

	createBasicBlock(a, "", f);

	assert(a.isDefined());
	assert(_addr2fnc.count(a) == 0);

	_addr2fnc[a] = f;
	_fnc2addr[f] = a;

	return f;
}

//
//==============================================================================
// Basic block helper methods.
//==============================================================================
//

/**
 * \return Start address for basic block \p f.
 */
retdec::utils::Address Decoder::getBasicBlockAddress(llvm::BasicBlock* b)
{
	auto fIt = _bb2addr.find(b);
	return fIt != _bb2addr.end() ? fIt->second : Address();
}

/**
 * \return End address for basic block \p b - the end address of the last
 *         instruction in the basic block.
 */
retdec::utils::Address Decoder::getBasicBlockEndAddress(llvm::BasicBlock* b)
{
	if (b == nullptr)
	{
		Address();
	}

	if (b->empty())
	{
		return getBasicBlockAddress(b);
	}

	AsmInstruction ai(&b->back());
	return ai.getEndAddress();
}

/**
 * \return basic block exactly at address \p a.
 */
llvm::BasicBlock* Decoder::getBasicBlockAtAddress(retdec::utils::Address a)
{
	auto fIt = _addr2bb.find(a);
	return fIt != _addr2bb.end() ? fIt->second : nullptr;
}

/**
 * \return The first basic block before or at address \p a.
 */
llvm::BasicBlock* Decoder::getBasicBlockBeforeAddress(
		retdec::utils::Address a)
{
	if (_addr2bb.empty())
	{
		return nullptr;
	}

	// Iterator to the first element whose key goes after a.
	auto it = _addr2bb.upper_bound(a);

	// The first BB is after a -> no BB before a.
	if (it == _addr2bb.begin())
	{
		return nullptr;
	}
	// No BB after a -> the last BB before a.
	else if (it == _addr2bb.end())
	{
		return _addr2bb.rbegin()->second;
	}
	// BB after a exists -> the one before it is before a.
	else
	{
		--it;
		return it->second;
	}
}

/**
 * \return Basic block that contains the address \p a. I.e. \p a is between
 * basic blocks's start and end address.
 */
llvm::BasicBlock* Decoder::getBasicBlockContainingAddress(
		retdec::utils::Address a)
{
	auto* f = getBasicBlockBeforeAddress(a);
	Address end = getBasicBlockEndAddress(f);
	return a.isDefined() && end.isDefined() && a < end ? f : nullptr;
}

/**
 * Create basic block at address \p a with name \p name in function \p f right
 * after basic block \p insertAfter.
 * \return Created function.
 */
llvm::BasicBlock* Decoder::createBasicBlock(
		retdec::utils::Address a,
		const std::string& name,
		llvm::Function* f,
		llvm::BasicBlock* insertAfter)
{
	std::string n = name.empty() ? "bb_" + a.toHexString() : name;

	auto* next = insertAfter ? insertAfter->getNextNode() : nullptr;

	auto* b = llvm::BasicBlock::Create(
			_module->getContext(),
			n,
			f,
			next);

	llvm::IRBuilder<> irb(b);
	irb.CreateRet(llvm::UndefValue::get(f->getReturnType()));

	_addr2bb[a] = b;
	_bb2addr[b] = a;

	return b;
}

bool Decoder::isNopInstruction(cs_insn* insn)
{
	if (_config->getConfig().architecture.isX86())
	{
		return isNopInstruction_x86(insn);
	}

	return false;
}

bool Decoder::isNopInstruction_x86(cs_insn* insn)
{
	cs_x86& insn86 = insn->detail->x86;

	if (insn->id == X86_INS_NOP
			|| insn->id == X86_INS_FNOP
			|| insn->id == X86_INS_FDISI8087_NOP
			|| insn->id == X86_INS_FENI8087_NOP
			|| insn->id == X86_INS_INT3)
	{
		return true;
	}
	// e.g. lea esi, [esi]
	//
	else if (insn->id == X86_INS_LEA
			&& insn86.disp == 0
			&& insn86.op_count == 2
			&& insn86.operands[0].type == X86_OP_REG
			&& insn86.operands[1].type == X86_OP_MEM
			&& insn86.operands[1].mem.segment == X86_REG_INVALID
			&& insn86.operands[1].mem.index == X86_REG_INVALID
			&& insn86.operands[1].mem.scale == 1
			&& insn86.operands[1].mem.disp == 0
			&& insn86.operands[1].mem.base == insn86.operands[0].reg)
	{
		return true;
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
