/**
* @file src/bin2llvmir/optimizations/decoder/decoder.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iostream>
#include <map>

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/CFG.h>

#include <json/json.h> // TODO

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/utils/defs.h"
#define debug_enabled true
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
	if (initTranslator())
	{
		LOG << "[ABORT] Unable to create capstone2llvmir translator.\n";
		return false;
	}

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

	// TODO:
	dumpModuleToFile(_module);
	dumpControFlowToJson();
	exit(1);
	return false;
}

/**
 * Initialize capstone2llvmir translator according to the architecture of
 * file to decompile.
 * @return @c True if error, @c false otherwise.
 */
bool Decoder::initTranslator()
{
	auto& a = _config->getConfig().architecture;

	cs_arch arch = CS_ARCH_ALL;
	cs_mode basicMode = CS_MODE_LITTLE_ENDIAN;
	cs_mode extraMode = a.isEndianBig()
			? CS_MODE_BIG_ENDIAN
			: CS_MODE_LITTLE_ENDIAN;

	if (a.isX86())
	{
		arch = CS_ARCH_X86;
		switch (_config->getConfig().architecture.getBitSize())
		{
			case 16: basicMode = CS_MODE_16; break;
			case 64: basicMode = CS_MODE_64; break;
			default:
			case 32: basicMode = CS_MODE_32; break;
		}
	}
	else if (_config->getConfig().architecture.isMipsOrPic32())
	{
		arch = CS_ARCH_MIPS;
		switch (_config->getConfig().architecture.getBitSize())
		{
			case 64: basicMode = CS_MODE_MIPS64; break;
			default:
			case 32: basicMode = CS_MODE_MIPS32; break;
		}
	}
	else if (_config->getConfig().architecture.isPpc())
	{
		arch = CS_ARCH_PPC;
		switch (_config->getConfig().architecture.getBitSize())
		{
			case 64: basicMode = CS_MODE_64; break;
			default:
			case 32: basicMode = CS_MODE_32; break;
		}
	}
	else if (_config->getConfig().architecture.isArmOrThumb()
			&& _config->getConfig().architecture.getBitSize() == 32)
	{
		arch = CS_ARCH_ARM;
		basicMode = CS_MODE_ARM;
	}

	_c2l = Capstone2LlvmIrTranslator::createArch(
			arch,
			_module,
			basicMode,
			extraMode);
	_currentMode = basicMode;
	return false;
}

/**
 * Synchronize metadata between capstone2llvmir and bin2llvmir.
 */
void Decoder::initEnvironment()
{
	initEnvironmentAsm2LlvmMapping();
	initEnvironmentPseudoFunctions();
	initEnvironmentRegisters();
}

/**
 * Find out from capstone2llvmir which global is used for
 * LLVM IR <-> Capstone ASM mapping.
 * 1. Set its name.
 * 2. Set it to config.
 * 3. Create metadata for it, so it can be quickly recognized without querying
 *    config.
 */
void Decoder::initEnvironmentAsm2LlvmMapping()
{
	auto* a2lGv = _c2l->getAsm2LlvmMapGlobalVariable();
	a2lGv->setName(_asm2llvmGv);

	_config->setLlvmToAsmGlobalVariable(a2lGv);

	auto* nmd = _module->getOrInsertNamedMetadata(_asm2llvmMd);
	auto* mdString = MDString::get(_module->getContext(), a2lGv->getName());
	auto* mdn = MDNode::get(_module->getContext(), {mdString});
	nmd->addOperand(mdn);
}

/**
 * Set pseudo functions' names in LLVM IR and set them to config.
 */
void Decoder::initEnvironmentPseudoFunctions()
{
	auto* cf = _c2l->getCallFunction();
	cf->setName(_callFunction);
	_config->setLlvmCallPseudoFunction(cf);

	auto* rf = _c2l->getReturnFunction();
	rf->setName(_returnFunction);
	_config->setLlvmReturnPseudoFunction(rf);

	auto* bf = _c2l->getBranchFunction();
	bf->setName(_branchFunction);
	_config->setLlvmBranchPseudoFunction(bf);

	auto* cbf = _c2l->getCondBranchFunction();
	cbf->setName(_condBranchFunction);
	_config->setLlvmCondBranchPseudoFunction(cbf);

	if (auto* c2lX86 = dynamic_cast<Capstone2LlvmIrTranslatorX86*>(_c2l.get()))
	{
		c2lX86->getX87DataLoadFunction()->setName(_x87dataLoadFunction);
		c2lX86->getX87TagLoadFunction()->setName(_x87tagLoadFunction);
		c2lX86->getX87DataStoreFunction()->setName(_x87dataStoreFunction);
		c2lX86->getX87TagStoreFunction()->setName(_x87tagStoreFunction);
	}
}

/**
 * Create config objects for HW registers.
 */
void Decoder::initEnvironmentRegisters()
{
	for (GlobalVariable& gv : _module->getGlobalList())
	{
		if (_c2l->isRegister(&gv))
		{
			unsigned regNum = _c2l->getCapstoneRegister(&gv);
			auto s = retdec::config::Storage::inRegister(
					gv.getName(),
					regNum,
					"");

			retdec::config::Object cr(gv.getName(), s);
			cr.type.setLlvmIr(llvmObjToString(gv.getValueType()));
			cr.setRealName(gv.getName());
			_config->getConfig().registers.insert(cr);
		}
	}
}

/**
 *
 */
void Decoder::initRanges()
{
	LOG << "\n initRanges():" << std::endl;

	if (!_config->getConfig().parameters.isSelectedDecodeOnly())
	{
		initAllowedRangesWithSegments();
	}
}

/**
 *
 */
void Decoder::initAllowedRangesWithSegments()
{
	LOG << "\n initAllowedRangesWithSegments():" << std::endl;

	auto* epSeg = _image->getImage()->getEpSegment();
	for (auto& seg : _image->getSegments())
	{
		auto* sec = seg->getSecSeg();
		Address start = seg->getAddress();
		Address end = seg->getPhysicalEndAddress();

		LOG << "\t" << seg->getName() << " @ " << start << " -- "
				<< end << std::endl;

		if (start == end)
		{
			LOG << "\t\tsize == 0 -> skipped" << std::endl;
			continue;
		}

		if (seg.get() != epSeg && sec)
		{
			if (auto* s = dynamic_cast<const PeCoffSection*>(sec))
			{
				if (s->getPeCoffFlags() & PeLib::PELIB_IMAGE_SCN_MEM_DISCARDABLE)
				{
					LOG << "\t\t" << "PeLib::PELIB_IMAGE_SCN_MEM_DISCARDABLE"
							" -> skipped" << std::endl;
					continue;
				}
			}
		}

		if (sec)
		{
			switch (sec->getType())
			{
				case SecSeg::Type::CODE:
					LOG << "\t\tcode section -> allowed ranges"
							<< std::endl;
					_allowedRanges.insert(start, end);
					break;
				case SecSeg::Type::DATA:
					LOG << "\t\tdata section -> alternative ranges"
							<< std::endl;
					_alternativeRanges.insert(start, end);
					break;
				case SecSeg::Type::CODE_DATA:
					LOG << "\t\tcode/data section -> alternative ranges"
							<< std::endl;
					_alternativeRanges.insert(start, end);
					break;
				case SecSeg::Type::CONST_DATA:
					if (seg.get() == epSeg)
					{
						LOG << "\t\tconst data section == ep seg "
								"-> alternative ranges" << std::endl;
						_alternativeRanges.insert(start, end);
					}
					else
					{
						LOG << "\t\tconst data section -> alternative ranges"
								<< std::endl;
						continue;
					}
					break;
				case SecSeg::Type::UNDEFINED_SEC_SEG:
					LOG << "\t\tundef section -> alternative ranges"
							<< std::endl;
					_alternativeRanges.insert(start, end);
					break;
				case SecSeg::Type::BSS:
					LOG << "\t\tbss section -> skipped" << std::endl;
					continue;
				case SecSeg::Type::DEBUG:
					LOG << "\t\tdebug section -> skipped" << std::endl;
					continue;
				case SecSeg::Type::INFO:
					LOG << "\t\tinfo section -> skipped" << std::endl;
					continue;
				default:
					assert(false && "unhandled section type");
					continue;
			}
		}
		else if (seg.get() == epSeg)
		{
			LOG << "\t\tno underlying section or segment && ep seg "
					"-> alternative ranges" << std::endl;
			_alternativeRanges.insert(start, end);
		}
		else
		{
			LOG << "\t\tno underlying section or segment -> skipped"
					<< std::endl;
			continue;
		}
	}

	for (auto& seg : _image->getSegments())
	{
		auto& rc = seg->getNonDecodableAddressRanges();
		for (auto& r : rc)
		{
			if (!r.contains(_config->getConfig().getEntryPoint()))
			{
				_allowedRanges.remove(r.getStart(), r.getEnd());
				_alternativeRanges.remove(r.getStart(), r.getEnd());
			}
		}
	}
}

void Decoder::initJumpTargets()
{
	LOG << "\n initJumpTargets():" << std::endl;

	auto mode = _c2l->getBasicMode();

	// Entry point.
	//
	LOG << "\tEntry point:" << std::endl;
	auto ep = _config->getConfig().getEntryPoint();
	if (ep.isDefined())
	{
		LOG << "\t\t ep @ " << ep << std::endl;

		if (isArmOrThumb())
		{
			mode = ep % 2 ? CS_MODE_THUMB : CS_MODE_ARM;
		}

		_jumpTargets.push(
				ep,
				JumpTarget::eType::ENTRY_POINT,
				mode,
				Address::getUndef,
				_entryPointFunction);
	}
}

bool Decoder::isArmOrThumb() const
{
	return _config->getConfig().architecture.isArmOrThumb();
}

void Decoder::decode()
{
	LOG << "\n doDecoding()" << std::endl;

	while (!_jumpTargets.empty())
	{
		JumpTarget jt = _jumpTargets.top();
		_jumpTargets.pop();
		LOG << "\tprocessing : " << jt << std::endl;

		decodeJumpTarget(jt);
	}
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
//		LOG << "\t\tfound no range -> skipped" << std::endl;
//		return;

		if (jt.type == JumpTarget::eType::CONTROL_FLOW_CALL_AFTER)
		{
			assert(false);
		}
		else if (jt.type == JumpTarget::eType::CONTROL_FLOW_COND_BR_FALSE)
		{
			auto* fromInst = jt.fromInst;
			auto* fromFnc = fromInst->getFunction();
			auto* targetBb = getBasicBlock(jt.address);

			if (targetBb == nullptr)
			{
				assert(false);
			}
			else if (targetBb->getParent() == fromFnc)
			{
				_pseudoWorklist.setTargetBbFalse(
						llvm::cast<llvm::CallInst>(jt.fromInst),
						targetBb);
				return;
			}
			else
			{
				assert(false);
			}
		}
		else if (jt.type == JumpTarget::eType::CONTROL_FLOW_COND_BR_TRUE)
		{
			auto* fromInst = jt.fromInst;
			auto* fromFnc = fromInst->getFunction();
			auto* targetBb = getBasicBlock(jt.address);

			if (targetBb == nullptr)
			{
				auto ai = AsmInstruction(_module, jt.address);
				if (ai.isValid() && ai.getFunction() == fromFnc)
				{
					auto* newBb = ai.makeStart();
					_pseudoWorklist.setTargetBbTrue(
							llvm::cast<llvm::CallInst>(jt.fromInst),
							newBb);
					return;
				}

				assert(false);
			}
			else if (targetBb->getParent() == fromFnc)
			{
				_pseudoWorklist.setTargetBbTrue(
						llvm::cast<llvm::CallInst>(jt.fromInst),
						targetBb);
				return;
			}
			else
			{
				assert(false);
			}
		}
		else if (jt.type == JumpTarget::eType::CONTROL_FLOW_BR_TARGET)
		{
			auto* fromInst = jt.fromInst;
			auto* fromFnc = fromInst->getFunction();
			auto* targetBb = getBasicBlock(jt.address);

			if (targetBb == nullptr)
			{
				auto ai = AsmInstruction(_module, jt.address);
				if (ai.isValid() && ai.getFunction() == fromFnc)
				{
					auto* newBb = ai.makeStart();
					_pseudoWorklist.setTargetBbTrue(
							llvm::cast<llvm::CallInst>(jt.fromInst),
							newBb);
					return;
				}

				assert(false);
			}
			else if (targetBb->getParent() == fromFnc)
			{
				_pseudoWorklist.setTargetBbTrue(
						llvm::cast<llvm::CallInst>(jt.fromInst),
						targetBb);
				return;
			}
			else
			{
				assert(false);
			}
		}
		else if (jt.type == JumpTarget::eType::CONTROL_FLOW_CALL_TARGET)
		{
			if (auto* f = getFunction(jt.address))
			{
				_pseudoWorklist.setTargetFunction(
						llvm::cast<llvm::CallInst>(jt.fromInst),
						f);
				return;
			}

//			std::cout << AsmInstruction(jt.fromInst) << std::endl;
//			std::cout << AsmInstruction(_module, jt.address) << std::endl;

//			assert(false);
			// TODO: split function
		}

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
	bytes.second = range->getSize() < bytes.second
			? range->getSize().getValue()
			: bytes.second;

//if (jt.doDryRun())
//{
//	// TODO: try dry run, based on jump target type:
//	// 1. ok   - ???
//	// 2. fail - ???
//	std::cout << "\n do dry run\n" << std::endl;
//	exit(1);
//}

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
			LOG << "\t\ttranslation failed" << std::endl;
			// TODO: we need to somehow close the BB.
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

llvm::IRBuilder<> Decoder::getIrBuilder(const JumpTarget& jt)
{
	if (_addr2fnc.empty() && jt.type == JumpTarget::eType::ENTRY_POINT)
	{
		auto* f = createFunction(jt.address, jt.getName());
		return llvm::IRBuilder<>(&f->front().front());
	}
	else if (jt.type == JumpTarget::eType::CONTROL_FLOW_CALL_AFTER)
	{
		auto* next = jt.fromInst->getNextNode();
		assert(next); // There should be at least a terminator instr.
		return llvm::IRBuilder<>(next);
	}
	else if (jt.type == JumpTarget::eType::CONTROL_FLOW_COND_BR_FALSE)
	{
		auto* bb = createBasicBlock(
				jt.address,
				jt.getName(),
				jt.fromInst->getFunction(),
				jt.fromInst->getParent());
		_pseudoWorklist.setTargetBbFalse(
				llvm::cast<llvm::CallInst>(jt.fromInst),
				bb);
		return llvm::IRBuilder<>(bb->getTerminator());
	}
	else if (jt.type == JumpTarget::eType::CONTROL_FLOW_COND_BR_TRUE)
	{
		auto* fromInst = jt.fromInst;
		auto* fromFnc = fromInst->getFunction();
		auto* targetFnc = getFunctionBeforeAddress(jt.address);

		if (targetFnc == nullptr)
		{
			assert(false);
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
					llvm::cast<llvm::CallInst>(jt.fromInst),
					newBb);

			return llvm::IRBuilder<>(newBb->getTerminator());
		}
		else
		{
			assert(false);
		}
	}
	else if (jt.type == JumpTarget::eType::CONTROL_FLOW_BR_TARGET)
	{
		auto* fromInst = jt.fromInst;
		auto* fromFnc = fromInst->getFunction();
		auto* targetFnc = getFunctionBeforeAddress(jt.address);

		if (targetFnc == nullptr)
		{
			auto* f = createFunction(jt.address, jt.getName());

			_pseudoWorklist.setTargetFunction(
					llvm::cast<llvm::CallInst>(jt.fromInst),
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
					llvm::cast<llvm::CallInst>(jt.fromInst),
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
						llvm::cast<llvm::CallInst>(jt.fromInst),
						f);

				return llvm::IRBuilder<>(&f->front().front());
			}
		}
	}
	else if (jt.type == JumpTarget::eType::CONTROL_FLOW_CALL_TARGET)
	{
		if (getFunction(jt.address))
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
					llvm::cast<llvm::CallInst>(jt.fromInst),
					f);

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

		_jumpTargets.push(
				nextAddr,
				JumpTarget::eType::CONTROL_FLOW_CALL_AFTER,
				m,
				tr.branchCall);
		LOG << "\t\t" << "call @ " << addr << " next " << nextAddr << std::endl;

		_pseudoWorklist.addPseudoCall(tr.branchCall);

		return true;
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
					JumpTarget::eType::CONTROL_FLOW_BR_TARGET,
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
					JumpTarget::eType::CONTROL_FLOW_COND_BR_TRUE,
					m,
					tr.branchCall);
			LOG << "\t\t" << "cond br @ " << addr << " -> (true) "
					<< t << std::endl;
		}

		_jumpTargets.push(
				nextAddr,
				JumpTarget::eType::CONTROL_FLOW_COND_BR_FALSE,
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

llvm::Type* Decoder::getDefaultFunctionReturnType()
{
	return llvm::Type::getInt32Ty(_module->getContext());
}

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
						getDefaultFunctionReturnType(),
						false),
				llvm::GlobalValue::ExternalLinkage,
				n,
				_module);
	}
	else
	{
		f = llvm::Function::Create(
				llvm::FunctionType::get(
						getDefaultFunctionReturnType(),
						false),
				llvm::GlobalValue::ExternalLinkage,
				n);

		auto* before = getFunctionBeforeAddress(a);
		if (before)
		{
			fl.insertAfter(before->getIterator(), f);
		}
		else
		{
			fl.insert(fl.begin(), f);
		}
	}

	createBasicBlock(a, "", f);

	_addr2fnc[a] = f;
	_fnc2addr[f] = a;

	return f;
}
llvm::Function* Decoder::getFunctionBeforeAddress(retdec::utils::Address a)
{
	if (_addr2fnc.empty())
	{
		return nullptr;
	}

	// Iterator to the first element whose key goes after a.
	auto it = _addr2fnc.upper_bound(a);

	// The first function is after a -> no function contains a.
	if (it == _addr2fnc.begin())
	{
		return nullptr;
	}
	// No function after a -> the last function contains a.
	else if (it == _addr2fnc.end())
	{
		return _addr2fnc.rbegin()->second;
	}
	// Function after a exists -> the one before it contains a.
	else
	{
		--it;
		return it->second;
	}
}
llvm::Function* Decoder::getFunctionContainingAddress(retdec::utils::Address a)
{
	auto* f = getFunctionBeforeAddress(a);
	Address end = getFunctionEndAddress(f);
	return a.isDefined() && end.isDefined() && a < end ? f : nullptr;
}
retdec::utils::Address Decoder::getFunctionAddress(llvm::Function* f)
{
	auto fIt = _fnc2addr.find(f);
	return fIt != _fnc2addr.end() ? fIt->second : Address();
}
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

	return AsmInstruction::getInstructionAddress(&f->back().back());
}
llvm::Function* Decoder::getFunction(retdec::utils::Address a)
{
	auto fIt = _addr2fnc.find(a);
	return fIt != _addr2fnc.end() ? fIt->second : nullptr;
}

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
llvm::BasicBlock* Decoder::getBasicBlockBeforeAddress(
		retdec::utils::Address a)
{
	if (_addr2bb.empty())
	{
		return nullptr;
	}

	// Iterator to the first element whose key goes after a.
	auto it = _addr2bb.upper_bound(a);

	// The first BB is after a -> no BB contains a.
	if (it == _addr2bb.begin())
	{
		return nullptr;
	}
	// No BB after a -> the last BB contains a.
	else if (it == _addr2bb.end())
	{
		return _addr2bb.rbegin()->second;
	}
	// BB after a exists -> the one before it contains a.
	else
	{
		--it;
		return it->second;
	}
}
retdec::utils::Address Decoder::getBasicBlockAddress(llvm::BasicBlock* b)
{
	auto fIt = _bb2addr.find(b);
	return fIt != _bb2addr.end() ? fIt->second : Address();
}
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

	return AsmInstruction::getInstructionAddress(&b->back());
}
llvm::BasicBlock* Decoder::getBasicBlock(retdec::utils::Address a)
{
	auto fIt = _addr2bb.find(a);
	return fIt != _addr2bb.end() ? fIt->second : nullptr;
}

//
//==============================================================================
// PseudoCallWorklist
//==============================================================================
//

void PseudoCallWorklist::addPseudoCall(llvm::CallInst* c)
{
	_worklist.emplace(c, PseudoCall(eType::CALL, c));
}

void PseudoCallWorklist::addPseudoBr(llvm::CallInst* c)
{
	_worklist.emplace(c, PseudoCall(eType::BR, c));
}

void PseudoCallWorklist::addPseudoCondBr(llvm::CallInst* c)
{
	_worklist.emplace(c, PseudoCall(eType::COND_BR, c));
}

void PseudoCallWorklist::addPseudoReturn(llvm::CallInst* c)
{
	// TODO: right now, we replace return right away,
	// this could be done later.
//	_worklist.emplace(c, PseudoCall(eType::RETURN, c));

	auto* f = c->getFunction();
	llvm::ReturnInst::Create(
			c->getModule()->getContext(),
			llvm::UndefValue::get(f->getReturnType()),
			c);
	c->eraseFromParent();
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

	assert(pc.type == eType::CALL || pc.type == eType::BR);

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

	assert(pc.type == eType::BR || pc.type == eType::COND_BR);

	pc.targetBbTrue = b;

	if (pc.type == eType::BR)
	{
		llvm::BranchInst::Create(pc.targetBbTrue, pc.pseudoCall);
		pc.pseudoCall->eraseFromParent();
		_worklist.erase(pc.pseudoCall);
	}
	else if (pc.type == eType::COND_BR && pc.targetBbFalse)
	{
		llvm::BranchInst::Create(
				pc.targetBbTrue,
				pc.targetBbFalse,
				pc.pseudoCall->getOperand(0),
				pc.pseudoCall);
		pc.pseudoCall->eraseFromParent();
		_worklist.erase(pc.pseudoCall);
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

	assert(pc.type == eType::COND_BR);

	pc.targetBbFalse = b;

	if (pc.targetBbTrue)
	{
		llvm::BranchInst::Create(
				pc.targetBbTrue,
				pc.targetBbFalse,
				pc.pseudoCall->getOperand(0),
				pc.pseudoCall);
		pc.pseudoCall->eraseFromParent();
		_worklist.erase(pc.pseudoCall);
	}
}

void Decoder::dumpControFlowToJson()
{
	Json::Value jsonFncs(Json::arrayValue);
	auto& fncs = _module->getFunctionList();
	for (llvm::Function& f : fncs)
	{
		Json::Value jsonFnc;

		jsonFnc["address"] = getFunctionAddress(&f).toHexPrefixString();
		jsonFnc["address_end"] = getFunctionEndAddress(&f).toHexPrefixString();

		Json::Value jsonBbs(Json::arrayValue);
		for (llvm::BasicBlock& bb : f)
		{
			Json::Value bbs;

			bbs["address"] = getBasicBlockAddress(&bb).toHexPrefixString();
			bbs["address_end"] = getBasicBlockEndAddress(&bb).toHexPrefixString();

			Json::Value jsonSuccs(Json::arrayValue);
			for (auto sit = succ_begin(&bb), e = succ_end(&bb); sit != e; ++sit)
			{
				auto* succ = *sit;
				jsonSuccs.append(getBasicBlockAddress(succ).toHexPrefixString());
			}
			bbs["succs"] = jsonSuccs;

			jsonBbs.append(bbs);
		}
		jsonFnc["bbs"] = jsonBbs;

		jsonFnc["code_refs"] = Json::arrayValue;

		jsonFncs.append(jsonFnc);
	}

	Json::StreamWriterBuilder builder;
	builder["commentStyle"] = "All";
	builder["indentation"] = "    ";
	builder["enableYAMLCompatibility"] = true; // " : " -> ": "
	builder["dropNullPlaceholders"] = false;
	std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());

	std::ofstream myfile("control-flow.json");
	writer->write(jsonFncs, &myfile);
}

} // namespace bin2llvmir
} // namespace retdec
