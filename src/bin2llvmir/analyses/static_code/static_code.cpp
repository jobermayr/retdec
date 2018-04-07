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

std::size_t StaticCodeFunction::countRefsOk() const
{
	std::size_t ret = 0;

	for (auto& ref : references)
	{
		ret += ref.ok;
	}

	return ret;
}

float StaticCodeFunction::refsOkShare() const
{
	return references.empty()
			? 1.0
			: float(countRefsOk()) / float(references.size());
}

std::string StaticCodeFunction::getName() const
{
	return names.empty() ? "" : names.front();
}

//
//==============================================================================
// StaticCodeAnalysis
//==============================================================================
//

StaticCodeAnalysis::StaticCodeAnalysis(
		Config* c,
		FileImage* i,
		NameContainer* ns,
		csh ce)
		:
		_config(c),
		_image(i),
		_names(ns),
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

	for (auto& p : _allDetections)
	{
		_worklistDetections.insert(&p.second);
	}

	confirmAllRefsOk();
	confirmPartialRefsOk();

	LOG << "\t Confirmed detections:" << std::endl;
	for (auto& p : _confirmedDetections)
	{
//		LOG << "\t\t" << p.first << " @ " << p.second->getName() << std::endl;
		LOG << "        " << "assert self.out_config.is_statically_linked('"
				<< p.second->getName() << "', " << p.first << ")"
				<< std::endl;
	}
	LOG << "\t Rejected detections:" << std::endl;
	for (auto& p : _rejectedDetections)
	{
//		LOG << "\t\t" << p.first << " @ " << p.second->getName() << std::endl;
		LOG << "        " << "assert not self.out_config.is_statically_linked('"
				<< p.second->getName() << "', " << p.first << ")"
				<< std::endl;
	}
	LOG << "\t Worklist detections:" << std::endl;
	for (auto* f : _worklistDetections)
	{
//		LOG << "\t\t" << f->address << " @ " << f->getName() << std::endl;
		LOG << "        " << "assert not self.out_config.is_statically_linked('"
				<< f->getName() << "', " << f->address << ")"
				<< std::endl;
	}
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

const StaticCodeAnalysis::DetectedFunctionsPtrMap&
StaticCodeAnalysis::getConfirmedDetections() const
{
	return _confirmedDetections;
}

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

	// TODO: make sure references do not point into detected function body
	// of the source function. e.g. reference to detected function does
	// not overlap with the original function.

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

void StaticCodeAnalysis::confirmAllRefsOk(std::size_t minFncSzWithoutRefs)
{
	LOG << "\t" << "confirmAllRefsOk()" << std::endl;

	// Sort all functions with all references OK by number of references.
	//
	std::multimap<std::size_t, StaticCodeFunction*> byRefNum;
	DetectedFunctionsPtrMultimap byAddress;
	for (auto* f : _worklistDetections)
	{
		if (f->allRefsOk())
		{
			byRefNum.emplace(f->references.size(), f);
			byAddress.emplace(f->address, f);
		}
	}
	LOG << "\t\t" << "byRefNum (sz = " << byRefNum.size() << "):" << std::endl;
	for (auto& p : byRefNum)
	{
		LOG << "\t\t\t" << p.first << " @ " << p.second->address
				<< " " << p.second->getName() << std::endl;
	}

	// From functions with the most references to those with at least one
	// reference, confirm function if:
	//   - No conflicting function at the same address.
	//   - Conflicting function is shorter or has less references.
	//   - Function has at least some reference or is not too short.
	//
	for (auto it = byRefNum.rbegin(), e = byRefNum.rend(); it != e; ++it)
	{
		auto* f = it->second;

		// Function was solved in the meantime.
		//
		if (_worklistDetections.count(f) == 0)
		{
			continue;
		}

		// Skip functions without references that are to short.
		//
		if (f->references.empty() && f->size < minFncSzWithoutRefs)
		{
			continue;
		}

		// Only one function at this address.
		//
		if (byAddress.count(f->address) == 1)
		{
			confirmFunction(f);
		}

		//
		//
		bool bestConflicting = true;
		auto eqr = byAddress.equal_range(f->address);
		for (auto it = eqr.first; it != eqr.second; ++it)
		{
			auto* of = it->second;
			if (f != of)
			{
				if (!(f->size > of->size
						|| f->references.size() > of->references.size()))
				{
					bestConflicting = false;
					break;
				}
			}
		}
		if (bestConflicting)
		{
			confirmFunction(f);
		}
	}
}

void StaticCodeAnalysis::confirmPartialRefsOk(float okShare)
{
	LOG << "\t" << "confirmPartialRefsOk()" << std::endl;

	while (true)
	{
		// Find the function with max ok share.
		//
		float maxShare = 0.0;
		StaticCodeFunction* f = nullptr;
		for (auto* of : _worklistDetections)
		{
			if (of->references.empty())
			{
				continue;
			}

			float ms = of->refsOkShare();
			if (ms > maxShare
					|| (ms == maxShare && f && of->size > f->size))
			{
				maxShare = ms;
				f = of;
			}
		}

		// Check if share ok.
		//
		if (f == nullptr || maxShare < okShare)
		{
			break;
		}
		LOG << "\t\t" << "[" << maxShare << "] " << f->address
				<< " @ " << f->getName() << std::endl;

		// This can increase ok share in other function by confirming all
		// (even unsolved) references in this function -> repeat loop.
		//
		confirmFunction(f);
	}
}

void StaticCodeAnalysis::confirmFunction(StaticCodeFunction* f)
{
	LOG << "\t\t" << "confirming " << f->getName() << " @ " << f->address
			<< std::endl;

	// Confirm the function.
	//
	_confirmedDetections.emplace(f->address, f);
	_worklistDetections.erase(f);
	for (auto& n : f->names)
	{
		_names->addNameForAddress(f->address, n, Name::eType::STATIC_CODE);
	}

	// Reject all other function at the same address.
	//
	auto eqr = _allDetections.equal_range(f->address);
	for (auto it = eqr.first; it != eqr.second; ++it)
	{
		auto* of = &it->second;
		if (of != f)
		{
			_rejectedDetections.emplace(of->address, of);
			_worklistDetections.erase(of);
		}
	}

	// Reject all functions that overlap with the function.
	//
	AddressRange range(f->address, f->address + f->size - 1);
	auto it = _worklistDetections.begin(), e = _worklistDetections.end();
	while (it != e)
	{
		auto* of = *it;
		if (of != f)
		{
			AddressRange oRange(of->address, of->address + of->size - 1);
			if (range.overlaps(oRange))
			{
				_rejectedDetections.emplace(of->address, of);
				it = _worklistDetections.erase(it);
				continue;
			}
		}
		++it;
	}

	// Confirm and make use of all references.
	//
	for (auto& r : f->references)
	{
		// Confirm all functions referenced from the function.
		//
		if (r.targetFnc && _worklistDetections.count(r.targetFnc))
		{
			confirmFunction(r.targetFnc);
		}

		// Confirm this reference in all detected functions.
		//
		if (!r.ok)
		{
			for (auto& p : _allDetections)
			for (auto& oref : p.second.references)
			{
				if (r.target == oref.target && r.name == oref.name)
				{
					oref.ok = true;
				}
			}
		}

		// Use names from references.
		//
		if (r.target.isDefined() && !r.name.empty())
		{
			_names->addNameForAddress(
					r.target,
					r.name,
					Name::eType::STATIC_CODE);
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
