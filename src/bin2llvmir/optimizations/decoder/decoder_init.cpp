/**
* @file src/bin2llvmir/optimizations/decoder/decoder.cpp
* @brief Various decoder initializations.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/utils/string.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace retdec::capstone2llvmir;
using namespace llvm;
using namespace retdec::fileformat;

namespace retdec {
namespace bin2llvmir {

/**
 * Initialize capstone2llvmir translator according to the architecture of
 * file to decompile.
 * @return @c True if error, @c false otherwise.
 */
void Decoder::initTranslator()
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
	else if (a.isMipsOrPic32())
	{
		arch = CS_ARCH_MIPS;
		switch (_config->getConfig().architecture.getBitSize())
		{
			case 64: basicMode = CS_MODE_MIPS64; break;
			default:
			case 32: basicMode = CS_MODE_MIPS32; break;
		}
	}
	else if (a.isPpc())
	{
		arch = CS_ARCH_PPC;
		switch (_config->getConfig().architecture.getBitSize())
		{
			case 64: basicMode = CS_MODE_64; break;
			default:
			case 32: basicMode = CS_MODE_32; break;
		}
	}
	else if (a.isArmOrThumb()
			&& a.getBitSize() == 32)
	{
		arch = CS_ARCH_ARM;
		basicMode = CS_MODE_ARM;
	}
	else
	{
		throw std::runtime_error("Unsupported architecture.");
	}

	_c2l = Capstone2LlvmIrTranslator::createArch(
			arch,
			_module,
			basicMode,
			extraMode);
	_currentMode = basicMode;
}

void Decoder::initDryRunCsInstruction()
{
	csh ce = _c2l->getCapstoneEngine();
	_dryCsInsn = cs_malloc(ce);
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
	for (GlobalVariable& gv : _module->globals())
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
 * Find address ranges to decode.
 */
void Decoder::initRanges()
{
	if (!_config->getConfig().parameters.isSelectedDecodeOnly())
	{
		initAllowedRangesWithSegments();
	}

	_originalAllowedRanges = _allowedRanges;
}

/**
 * Initialize address ranges to decode from image segments/sections.
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

/**
 * Find jump targets to decode.
 */
void Decoder::initJumpTargets()
{
	initJumpTargetsConfig();
	initJumpTargetsEntryPoint();
	initJumpTargetsImports();
	initJumpTargetsExports();
	initJumpTargetsDebug();
	initJumpTargetsSymbols();
}

void Decoder::initJumpTargetsConfig()
{
	LOG << "\n initJumpTargetsConfig():" << std::endl;

	for (auto& p : _config->getConfig().functions)
	{
		retdec::config::Function& f = p.second;
		if (f.getStart().isUndefined())
		{
			continue;
		}

		cs_mode m = _currentMode;
		if (_config->isArmOrThumb())
		{
			m = f.isThumb() ? CS_MODE_THUMB : CS_MODE_ARM;
		}

		utils::Maybe<std::size_t> sz;
		auto tmpSz = f.getSize();
		if (tmpSz.isDefined() && tmpSz > 0)
		{
			sz = tmpSz.getValue();
		}

		_jumpTargets.push(
				f.getStart(),
				JumpTarget::eType::CONFIG,
				m,
				Address::getUndef,
				sz);

		createFunction(f.getStart());

		LOG << "\tfunction @ " << f.getStart() << std::endl;
	}
}

void Decoder::initJumpTargetsEntryPoint()
{
	LOG << "\n initJumpTargetsEntryPoint():" << std::endl;

	auto ep = _config->getConfig().getEntryPoint();
	if (ep.isDefined())
	{
		cs_mode m = _currentMode;
		if (_config->isArmOrThumb())
		{
			m = ep % 2 ? CS_MODE_THUMB : CS_MODE_ARM;
		}

		_jumpTargets.push(
				ep,
				JumpTarget::eType::ENTRY_POINT,
				m,
				Address::getUndef);

		createFunction(ep);

		LOG << "\tentry point @ " << ep << std::endl;
	}
	else
	{
		LOG << "\tentry point @ UNDEFINED" << std::endl;
	}
}

void Decoder::initJumpTargetsImports()
{
	LOG << "\n initJumpTargetsImports():" << std::endl;

	auto* impTbl = _image->getFileFormat()->getImportTable();
	if (impTbl == nullptr)
	{
		LOG << "\tno import table -> skip" << std::endl;
		return;
	}

	for (const auto &imp : *impTbl)
	{
		retdec::utils::Address addr = imp.getAddress();
		if (addr.isUndefined())
		{
			continue;
		}

		std::string name = imp.getName();
		auto libN = impTbl->getLibrary(imp.getLibraryIndex());
		std::transform(libN.begin(), libN.end(), libN.begin(), ::tolower);

		if (name.empty())
		{
			unsigned long long ord = 0;
			if (!imp.getOrdinalNumber(ord))
			{
				continue;
			}

			name = "import_" + retdec::utils::removeSuffixRet(libN, ".dll")
					+ "_" + std::to_string(ord);
		}

		LOG << "\t\timport: " << imp.getName() << " @ " << addr << std::endl;

		auto* f = createFunction(addr, name, true);
		_imports.emplace(addr, name);

		if ((libN == "msvcrt.dll" && name == "exit")
				|| (libN == "msvcrt.dll" && name == "abort"))
		{
			_terminatingFncs.insert(f);
		}
	}
}

void Decoder::initJumpTargetsExports()
{
	LOG << "\n initJumpTargetsExports():" << std::endl;

	if (auto* exTbl = _image->getFileFormat()->getExportTable())
	{
		for (const auto& exp : *exTbl)
		{
			retdec::utils::Address addr = exp.getAddress();
			if (addr.isUndefined())
			{
				continue;
			}

			cs_mode m = _currentMode;
			if (_config->isArmOrThumb())
			{
				m = addr % 2 ? CS_MODE_THUMB : CS_MODE_ARM;
			}

			_jumpTargets.push(
					addr,
					JumpTarget::eType::EXPORT,
					m,
					Address::getUndef);

			createFunction(addr);
			_exports.insert(addr);

			LOG << "\t\texport @ " << addr << std::endl;
		}
	}
}

void Decoder::initJumpTargetsSymbols()
{
	LOG << "\n initJumpTargetsSymbols():" << std::endl;

	for (const auto* t : _image->getFileFormat()->getSymbolTables())
	for (const auto& s : *t)
	{
		if (!s->isFunction())
		{
			continue;
		}
		unsigned long long a = 0;
		if (!s->getRealAddress(a))
		{
			continue;
		}
		retdec::utils::Address addr = a;
		if (addr.isUndefined())
		{
			continue;
		}

		cs_mode m = _currentMode;
		if (_config->isArmOrThumb())
		{
			m = addr % 2 || s->isThumbSymbol() ? CS_MODE_THUMB : CS_MODE_ARM;
		}

		utils::Maybe<std::size_t> sz;
		unsigned long long tmpSz = 0;
		if (s->getSize(tmpSz) && tmpSz > 0)
		{
			sz = tmpSz;
		}

		if (s->getType() == retdec::fileformat::Symbol::Type::PUBLIC)
		{
			_jumpTargets.push(
					addr,
					JumpTarget::eType::SYMBOL_PUBLIC,
					m,
					Address::getUndef,
					sz);

			createFunction(addr);

			LOG << "\tsymbol public @ " << addr << std::endl;
		}
		else
		{
			_jumpTargets.push(
					addr,
					JumpTarget::eType::SYMBOL,
					m,
					Address::getUndef,
					sz);

			createFunction(addr);

			LOG << "\tsymbol @ " << addr << std::endl;
		}
	}
}

void Decoder::initJumpTargetsDebug()
{
	LOG << "\n initJumpTargetsDebug():" << std::endl;

	if (_debug)
	{
		LOG << "\tno debug info -> skip" << std::endl;
		return;
	}

	for (const auto& p : _debug->functions)
	{
		retdec::utils::Address addr = p.first;
		if (addr.isUndefined())
		{
			continue;
		}
		auto& f = p.second;

		LOG << "\tdebug @ " << addr << std::endl;

		cs_mode m = _currentMode;
		if (_config->isArmOrThumb())
		{
			m = addr % 2 || f.isThumb() ? CS_MODE_THUMB : CS_MODE_ARM;
		}

		utils::Maybe<std::size_t> sz;
		auto tmpSz = p.second.getSize();
		if (tmpSz.isDefined() && tmpSz > 0)
		{
			sz = tmpSz.getValue();
		}

		_jumpTargets.push(
				addr,
				JumpTarget::eType::DEBUG,
				m,
				Address::getUndef,
				sz);

		createFunction(addr);
		_debugFncs.insert(addr);

		LOG << "\tdebug @ " << addr << std::endl;
	}
}

void Decoder::initConfigFunction()
{
	for (auto& p : _fnc2addr)
	{
		Function* f = p.first;
		Address start = p.second;
		Address end = start;

		if (!f->empty() && !f->back().empty())
		{
			if (auto ai = AsmInstruction(&f->back().back()))
			{
				end = ai.getEndAddress() - 1;
			}
		}

		auto* cf = _config->insertFunction(f, p.second, end);
		if (_imports.count(start))
		{
			cf->setIsDynamicallyLinked();
		}

		cf->setIsExported(_exports.count(start));
		cf->setIsFromDebug(_debugFncs.count(start));
	}
}

} // namespace bin2llvmir
} // namespace retdec
