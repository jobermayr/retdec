/**
* @file src/bin2llvmir/analyses/static_code/static_code.cpp
* @brief Static code analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/analyses/static_code/static_code.h"
#include "retdec/utils/string.h"

// Debug logs enabled/disabled.
#include "retdec/bin2llvmir/utils/defs.h"
#define debug_enabled true

using namespace retdec::stacofin;
using namespace retdec::utils;

//
//==============================================================================
// Anonymous namespace.
//==============================================================================
//

namespace {

using namespace retdec;
using namespace retdec::bin2llvmir;

void selectSignaturesWithName(
		const std::set<std::string>& src,
		std::set<std::string>& dst,
		const std::string& partOfName)
{
	for (const auto& sig : src)
	{
		if (sig.find(partOfName) != std::string::npos)
		{
			dst.insert(sig);
			LOG << "\t\t" << sig << std::endl;
		}
	}
}

void selectSignaturesWithNames(
		const std::set<std::string>& src,
		std::set<std::string>& dst,
		const std::set<std::string>& partOfName,
		const std::set<std::string>& notPartOfName)
{
	for (const auto& sig : src)
	{
		bool allOk = true;

		for (auto& p : partOfName)
		{
			if (sig.find(p) == std::string::npos)
			{
				allOk = false;
				break;
			}
		}

		for (auto& p : notPartOfName)
		{
			if (sig.find(p) != std::string::npos)
			{
				allOk = false;
				break;
			}
		}

		if (allOk)
		{
			dst.insert(sig);
			LOG << "\t\t" << sig << std::endl;
		}
	}
}

std::set<std::string> selectSignaturePaths(FileImage* image, Config* config)
{
	LOG << "\t selectSignaturePaths():" << std::endl;

	const retdec::config::Config& c = config->getConfig();

	std::set<std::string> sigs;

	// Add all statically linked signatures specified by user.
	//
	sigs = c.parameters.userStaticSignaturePaths;

	// Select only specific signatures from retdec's database.
	//
	auto& allSigs = c.parameters.staticSignaturePaths;

	std::set<std::string> vsSigsAll;
	std::set<std::string> vsSigsSpecific;
	if (c.tools.isMsvc())
	{
		selectSignaturesWithName(allSigs, sigs, "ucrt");

		std::string arch;
		if (c.architecture.isX86())
		{
			arch = "x86";
		}
		else if (c.architecture.isArmOrThumb())
		{
			arch = "arm";
		}

		std::size_t major = 0;
		std::size_t minor = 0;
		if (auto* pe = dynamic_cast<retdec::fileformat::PeFormat*>(
				image->getFileFormat()))
		{
			major = pe->getMajorLinkerVersion();
			minor = pe->getMinorLinkerVersion();

			if (major == 7 && minor == 1)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2003");
			}
			else if (major == 8 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2005");
			}
			else if (major == 9 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2008");
			}
			else if (major == 10 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2010");
			}
			else if (major == 11 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2012");
			}
			else if (major == 12 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2013");
			}
			else if (major == 14 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2015");
			}
			else if ((major == 15 && minor == 0)
					|| (major == 14 && minor == 10))
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2017");
			}
		}

		for (auto& vs : c.tools)
		{
			bool all = false;
			std::string pattern = arch;

			if (vs.isMsvc("debug"))
			{
				pattern += "debug-vs-";
			}
			else
			{
				pattern += "-vs-";
			}

			if (vs.isMsvc("7.1"))
			{
				pattern += "2003";
			}
			else if (vs.isMsvc("8.0"))
			{
				pattern += "2005";
			}
			else if (vs.isMsvc("9.0"))
			{
				pattern += "2008";
			}
			else if (vs.isMsvc("10.0"))
			{
				pattern += "2010";
			}
			else if (vs.isMsvc("11.0"))
			{
				pattern += "2012";
			}
			else if (vs.isMsvc("12.0"))
			{
				pattern += "2013";
			}
			else if (vs.isMsvc("14.0"))
			{
				pattern += "2015";
			}
			else if (vs.isMsvc("15.0"))
			{
				pattern += "2017";
			}
			else
			{
				all = true;
			}

			if (all)
			{
				selectSignaturesWithName(allSigs, vsSigsAll, pattern);
			}
			else
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, pattern);
			}
		}
	}
	if (!vsSigsSpecific.empty())
	{
		sigs.insert(vsSigsSpecific.begin(), vsSigsSpecific.end());
	}
	else
	{
		sigs.insert(vsSigsAll.begin(), vsSigsAll.end());
	}

	if (c.tools.isMingw())
	{
		if (c.tools.isTool("4.7.3"))
		{
			selectSignaturesWithName(allSigs, sigs, "mingw-4.7.3");
		}
		else if (c.tools.isTool("4.4.0"))
		{
			selectSignaturesWithName(allSigs, sigs, "mingw-4.4.0");
		}
	}
	else if (c.tools.isGcc() || c.tools.isLlvm())
	{
		if (c.tools.isPspGcc()
				&& c.tools.isTool("4.3.5"))
		{
			selectSignaturesWithNames(
					allSigs,
					sigs,
					{"psp-gcc-4.3.5"},
					{"pic32", "uClibc"});
		}
		else if (c.tools.isPic32()
				&& c.tools.isTool("4.5.2"))
		{
			selectSignaturesWithNames(
					allSigs,
					sigs,
					{"pic32-gcc-4.5.2"},
					{"psp", "uClibc"});
		}
		else if (c.fileFormat.isPe())
		{
			if (c.tools.isTool("4.7.3"))
			{
				selectSignaturesWithName(allSigs, sigs, "mingw-4.7.3");
			}
			else if (c.tools.isTool("4.4.0"))
			{
				selectSignaturesWithName(allSigs, sigs, "mingw-4.4.0");
			}
		}
		else // if (c.tools.isGcc())
		{
			if (c.tools.isTool("4.8.3"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{"gcc-4.8.3"},
						{"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.7.2"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{"gcc-4.7.2"},
						{"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.4.1"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{"gcc-4.4.1"},
						{"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.5.2"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{"gcc-4.5.2"},
						{"psp", "pic32", "uClibc"});
			}
		}
	}

	if (c.fileFormat.isIntelHex() || c.fileFormat.isRaw())
	{
		if (c.architecture.isMips())
		{
			selectSignaturesWithNames(allSigs, sigs, {"psp-gcc"}, {"uClibc"});
		}
		if (c.architecture.isPic32())
		{
			selectSignaturesWithNames(allSigs, sigs, {"pic32-gcc"}, {"uClibc"});
		}
	}

	if (c.tools.isDelphi())
	{
		selectSignaturesWithName(allSigs, sigs, "kb7");
	}

	return sigs;
}

void searchInSignaturePaths(
		stacofin::Finder& codeFinder,
		std::set<std::string>& sigPaths,
		FileImage* image)
{
	for (const auto &path : sigPaths)
	{
		codeFinder.search(*image->getImage(), path);
	}
}

void collectImports(
		FileImage* image,
		std::map<utils::Address, std::string>& imports)
{
	LOG << "\t collectImports():" << std::endl;

	if (auto* impTbl = image->getFileFormat()->getImportTable())
	for (const auto &imp : *impTbl)
	{
		retdec::utils::Address addr = imp.getAddress();
		if (addr.isUndefined())
		{
			continue;
		}

		imports.emplace(addr, imp.getName());
		LOG << "\t\t" << addr << " @ " << imp.getName() << std::endl;
	}
}

std::string dumpDetectedFunctions(
		stacofin::Finder& codeFinder,
		FileImage* image)
{
	std::stringstream ret;
	ret << "\t Detected functions (stacofin):" << "\n";
	for (auto& f : codeFinder.accessDectedFunctions())
	{
		ret << "\t\t" << f.address << " @ " << f.names.front()
				<< ", sz = " << f.size << "\n";

		for (auto& p : f.references)
		{
			Address refAddr = f.address + p.first;

			ret << "\t\t\t" << refAddr << " @ " << p.second;

			uint64_t val = 0;
			if (image->getImage()->getWord(refAddr, val))
			{
				ret << ", val = " << val;
			}

			ret << "\n";
		}
	}

	return ret.str();
}

std::string dumpDetectedFunctions(
		const StaticCodeAnalysis::DetectedFunctionsMultimap& allDetections)
{
	std::stringstream ret;
	ret << "\t Detected functions (bin2llvmir):" << "\n";
	for (auto& p : allDetections)
	{
		auto& f = p.second;

		ret << "\t\t" << (p.second.allRefsOk() ? "[+] " : "[-] ")
				<< f.address << " @ " << f.names.front()
				<< ", sz = " << f.size << "\n";

		for (auto& ref : f.references)
		{
			ret << "\t\t\t" << (ref.ok ? "[+] " : "[-] ")
					<< ref.address << " @ " << ref.name
					<< " -> " << ref.target << "\n";
		}
	}

	return ret.str();
}

} // namespace anonymous

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// StaticCodeFunction.
//==============================================================================
//

StaticCodeFunction::Reference::Reference(
		std::size_t o,
		utils::Address a,
		const std::string& n,
		utils::Address t,
		StaticCodeFunction* tf,
		bool k)
		:
		offset(o),
		address(a),
		name(n),
		target(t),
		targetFnc(tf),
		ok(k)
{

}

StaticCodeFunction::StaticCodeFunction(const stacofin::DetectedFunction& df) :
		address(df.address),
		size(df.size),
		names(df.names),
		signaturePath(df.signaturePath)
{
	for (auto& r : df.references)
	{
		references.emplace_back(r.first, r.first + address, r.second);
	}
}

bool StaticCodeFunction::allRefsOk() const
{
	for (auto& ref : references)
	{
		if (!ref.ok)
		{
			return false;
		}
	}

	return true;
}

//
//==============================================================================
// StaticCodeAnalysis
//==============================================================================
//

StaticCodeAnalysis::StaticCodeAnalysis(Config* c, FileImage* i, csh ce) :
		_config(c),
		_image(i),
		_ce(ce),
		_ceInsn(cs_malloc(ce))
{
	LOG << "\n StaticCodeAnalysis():" << std::endl;

	_sigPaths = selectSignaturePaths(_image, _config);

	searchInSignaturePaths(_codeFinder, _sigPaths, _image);
	LOG << dumpDetectedFunctions(_codeFinder, _image) << std::endl;

	collectImports(_image, _imports);

	for (auto& f : _codeFinder.accessDectedFunctions())
	{
		_allDetections.emplace(f.address, StaticCodeFunction(f));
	}

	LOG << dumpDetectedFunctions(_allDetections) << std::endl;
	solveReferences();
	LOG << dumpDetectedFunctions(_allDetections) << std::endl;

exit(1);
}

StaticCodeAnalysis::~StaticCodeAnalysis()
{
	cs_free(_ceInsn, 1);
}

void StaticCodeAnalysis::solveReferences()
{
	for (auto& p : _allDetections)
	for (auto& r : p.second.references)
	{
		r.target = getAddressFromRef(r.address);
		checkRef(r);
	}
}

const StaticCodeAnalysis::DetectedFunctionsMultimap&
StaticCodeAnalysis::getAllDetections() const
{
	return _allDetections;
}

const StaticCodeAnalysis::DetectedFunctionsMap&
StaticCodeAnalysis::getConfirmedDetections() const
{
	return _confirmedDetections;
}

//void StaticCodeAnalysis::strictSolve()
//{
//	bool changed = true;
//	while (changed && !_worklistDetections.empty())
//	{
//		changed = false;
//
//		for (auto wIt = _worklistDetections.begin(),
//				e = _worklistDetections.end();
//				wIt != e;)
//		{
//			auto& f = wIt->second;
//
//			bool allRefsOk = true;
//			for (auto& p : f.references)
//			{
//				Address refAddr = f.address + p.first;
//				if (_solvedRefs.count(refAddr))
//				{
//					continue;
//				}
//				std::string& refedName = p.second;
//
//				checkRef(refAddr, refedName);
//			}
//
//			if (allRefsOk)
//			{
//				_confirmedDetections.emplace(f.address, f);
//				wIt = _worklistDetections.erase(wIt);
//				changed = true;
//			}
//			else
//			{
//				++wIt;
//			}
//		}
//	}
//
//	changed = true;
//	while (changed && !_worklistDetections.empty())
//	{
//		changed = false;
//
//		for (auto& p : _confirmedDetections)
//		{
//			Address addr = p.first;
//			Address endAddr = addr + p.second.size;
//			for (auto it = _solvedRefs.lower_bound(addr);
//					it != _solvedRefs.end() && it->first < endAddr;
//					++it)
//			{
//				Address& ra = it->second.first;
//				std::string& rn = it->second.second;
//
//				auto fIt = _worklistDetections.equal_range(ra);
//				for (auto it=fIt.first; it!=fIt.second; ++it)
//				{
//					if (hasItem(it->second.names, rn))
//					{
//						_confirmedDetections.emplace(it->first, it->second);
//						_worklistDetections.erase(it);
//						changed = true;
//						break;
//					}
//				}
//			}
//		}
//	}
//
//	LOG << "\tConfirmed functions:" << std::endl;
//	for (auto& p : _confirmedDetections)
//	{
//		LOG << "\t\t" << p.first << " @ " << p.second.names.front() << std::endl;
//	}
//	LOG << "\tRejected functions:" << std::endl;
//	for (auto& p : _rerectedDetections)
//	{
//		LOG << "\t\t" << p.first << " @ " << p.second.names.front() << std::endl;
//	}
//	LOG << "\tWorklist functions:" << std::endl;
//	for (auto& p : _worklistDetections)
//	{
//		LOG << "\t\t" << p.first << " @ " << p.second.names.front() << std::endl;
//	}
//}

utils::Address StaticCodeAnalysis::getAddressFromRef(utils::Address ref)
{
	if (_config->getConfig().architecture.isX86_32())
	{
		return getAddressFromRef_x86(ref);
	}
	else
	{
		assert(false);
		return Address();
	}
}

utils::Address StaticCodeAnalysis::getAddressFromRef_x86(utils::Address ref)
{
	uint64_t val = 0;
	if (!_image->getImage()->getWord(ref, val))
	{
		return Address();
	}

	Address absAddr = val;
	Address addrAfterRef = ref + _image->getImage()->getBytesPerWord();
	Address relAddr = addrAfterRef + int32_t(val);

	auto imgBase = _image->getImage()->getBaseAddress();
	if (absAddr == imgBase)
	{
		return absAddr;
	}
	else if (relAddr == imgBase)
	{
		return relAddr;
	}

	bool absOk = _image->getImage()->hasDataOnAddress(absAddr);
	bool relOk = _image->getImage()->hasDataOnAddress(relAddr);

	if (absOk && !relOk)
	{
		return absAddr;
	}
	else if (!absOk && relOk)
	{
		return relAddr;
	}
	else if (absOk && relOk)
	{
		// both ok, what now?
		assert(false);
		return absAddr;
	}
	else
	{
		// default
		return absAddr;
	}

	return Address();
}

void StaticCodeAnalysis::checkRef(StaticCodeFunction::Reference& ref)
{
	if (ref.target.isUndefined())
	{
		return;
	}

	// Reference to detected function.
	//
	auto dIt = _allDetections.equal_range(ref.target);
	if (dIt.first != dIt.second)
	{
		for (auto it = dIt.first, e = dIt.second; it != e; ++it)
		{
			if (hasItem(it->second.names, ref.name))
			{
				ref.targetFnc = &it->second;
				ref.ok = true;
			}
		}

		return;
	}

	// Reference to import.
	//
	auto fIt = _imports.find(ref.target);
	if (fIt != _imports.end())
	{
		if (utils::contains(fIt->second, ref.name)
				|| utils::contains(ref.name, fIt->second))
		{
			ref.ok = true;
		}

		return;
	}

	// Reference to image base.
	//
	if (ref.target == _image->getImage()->getBaseAddress()
			&& ref.name == "__image_base__")
	{
		ref.ok = true;
		return;
	}

	// Reference into section with reference name equal to section name.
	//
	auto* seg = _image->getImage()->getSegmentFromAddress(ref.target);
	if (seg && seg->getName() == ref.name)
	{
		ref.ok = true;
		return;
	}

	// Architecture specific ckecks.
	//
	if (_config->getConfig().architecture.isX86())
	{
		checkRef_x86(ref);
	}
	if (ref.ok)
	{
		return;
	}

	// Reference into section with reference name set to some object name.
	// This must be the last check, because it can hit anything.
	//
	auto* sec = seg ? seg->getSecSeg() : nullptr;
	if (sec
			&& (sec->getType() == fileformat::SecSeg::Type::DATA
// Disabled because we can not distinguish between functions and data objects.
// We would like to hit data objects even in CODE section.
// But this could also falsely hit missing functions - e.g. we expect
// statically linked function on some address, but do not find it there,
// the first check in this list fails, but this will still succeed.
//					|| sec->getType() == fileformat::SecSeg::Type::CODE
					|| sec->getType() == fileformat::SecSeg::Type::CODE_DATA
					|| sec->getType() == fileformat::SecSeg::Type::CONST_DATA
					|| sec->getType() == fileformat::SecSeg::Type::BSS))
	{
		ref.ok = true;
		return;
	}

	// Reference to one byte after some section.
	// e.g. ___RUNTIME_PSEUDO_RELOC_LIST_END__ on x86 after .rdata
	//
	if (seg == nullptr
			&& _image->getImage()->getSegmentFromAddress(ref.target-1))
	{
		ref.ok = true;
		return;
	}
}

void StaticCodeAnalysis::checkRef_x86(StaticCodeFunction::Reference& ref)
{
	if (ref.target.isUndefined())
	{
		return;
	}

	uint64_t addr = ref.target;
	auto bytes = _image->getImage()->getRawSegmentData(ref.target);
	if (cs_disasm_iter(_ce, &bytes.first, &bytes.second, &addr, _ceInsn))
	{
		auto& x86 = _ceInsn->detail->x86;

		// Pattern: reference to stub function jumping to import:
		//     _localeconv     proc near
		//     FF 25 E0 B1 40 00        jmp ds:__imp__localeconv
		//     _localeconv     endp
		//
		if (_ceInsn->id == X86_INS_JMP
				&& x86.op_count == 1
				&& x86.operands[0].type == X86_OP_MEM
				&& x86.operands[0].mem.segment == X86_REG_INVALID
				&& x86.operands[0].mem.base == X86_REG_INVALID
				&& x86.operands[0].mem.index == X86_REG_INVALID
				&& x86.operands[0].mem.scale == 1
				&& x86.operands[0].mem.disp)
		{
			auto fIt = _imports.find(x86.operands[0].mem.disp);
			if (fIt != _imports.end())
			{
				if (utils::contains(fIt->second, ref.name)
						|| utils::contains(ref.name, fIt->second))
				{
					ref.ok = true;
				}

				return;
			}
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
