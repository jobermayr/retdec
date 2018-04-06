/**
* @file src/bin2llvmir/analyses/static_code/static_code.cpp
* @brief Static code analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/analyses/static_code/static_code.h"

// Debug logs enabled/disabled.
#include "retdec/bin2llvmir/utils/defs.h"
#define debug_enabled true

using namespace retdec::stacofin;
using namespace retdec::utils;

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
	ret << "\t Detected functions:" << "\n";
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

} // namespace anonymous

namespace retdec {
namespace bin2llvmir {

StaticCodeAnalysis::StaticCodeAnalysis(Config* c, FileImage* i) :
		_config(c),
		_image(i)
{
	LOG << "\n StaticCodeAnalysis():" << std::endl;

	_sigPaths = selectSignaturePaths(_image, _config);

	searchInSignaturePaths(_codeFinder, _sigPaths, _image);
	LOG << dumpDetectedFunctions(_codeFinder, _image) << std::endl;

	collectImports(_image, _imports);

	for (auto& f : _codeFinder.accessDectedFunctions())
	{
		_allDetections.emplace(f.address, f);
	}
	_worklistDetections = _allDetections;

	strictSolve();

exit(1);
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

void StaticCodeAnalysis::strictSolve()
{
	bool changed = true;
	while (changed && !_worklistDetections.empty())
	{
		changed = false;

		for (auto wIt = _worklistDetections.begin(),
				e = _worklistDetections.end();
				wIt != e;)
		{
			auto& f = wIt->second;

			bool allRefsOk = true;
			for (auto& p : f.references)
			{
				Address refAddr = f.address + p.first;
				if (_solvedRefs.count(refAddr))
				{
					continue;
				}
				std::string& refedName = p.second;

				checkRef(refAddr, refedName);
			}

			if (allRefsOk)
			{
				_confirmedDetections.emplace(f.address, f);
				wIt = _worklistDetections.erase(wIt);
				changed = true;
			}
			else
			{
				++wIt;
			}
		}
	}

	changed = true;
	while (changed && !_worklistDetections.empty())
	{
		changed = false;

		for (auto& p : _confirmedDetections)
		{
			Address addr = p.first;
			Address endAddr = addr + p.second.size;
			for (auto it = _solvedRefs.lower_bound(addr);
					it != _solvedRefs.end() && it->first < endAddr;
					++it)
			{
				Address& ra = it->second.first;
				std::string& rn = it->second.second;

				auto fIt = _worklistDetections.equal_range(ra);
				for (auto it=fIt.first; it!=fIt.second; ++it)
				{
					if (hasItem(it->second.names, rn))
					{
						_confirmedDetections.emplace(it->first, it->second);
						_worklistDetections.erase(it);
						changed = true;
						break;
					}
				}
			}
		}
	}

	LOG << "\tConfirmed functions:" << std::endl;
	for (auto& p : _confirmedDetections)
	{
		LOG << "\t\t" << p.first << " @ " << p.second.names.front() << std::endl;
	}
	LOG << "\tRejected functions:" << std::endl;
	for (auto& p : _rerectedDetections)
	{
		LOG << "\t\t" << p.first << " @ " << p.second.names.front() << std::endl;
	}
	LOG << "\tWorklist functions:" << std::endl;
	for (auto& p : _worklistDetections)
	{
		LOG << "\t\t" << p.first << " @ " << p.second.names.front() << std::endl;
	}
}

bool StaticCodeAnalysis::checkRef(utils::Address ref, const std::string& name)
{
	uint64_t val = 0;
	if (!_image->getImage()->getWord(refAddr, val))
	{
		allRefsOk = false;
		break;
	}

	Address absAddr = val;
	Address addrAfterRef = refAddr + _image->getImage()->getBytesPerWord();
	Address relAddr = addrAfterRef + int32_t(val); // TODO: arch size specific

	auto absCdIt = _confirmedDetections.find(absAddr);
	auto relCdIt = _confirmedDetections.find(relAddr);

	// Absolute address of detected function.
	//
	if (absCdIt != _confirmedDetections.end()
			&& hasItem(absCdIt->second.names, refedName))
	{
		_solvedRefs[refAddr] = std::make_pair(absAddr, refedName);
		// ok
	}
	// Absolute address of imported function.
	//
	else if (_imports.count(absAddr)
			&& _imports[absAddr] == refedName)
	{
		_solvedRefs[refAddr] = std::make_pair(absAddr, refedName);
		// ok
	}
	// Absolute address of data in named section.
	//
	else if (_image->getImage()->getSegmentFromAddress(absAddr)
			&& _image->getImage()->getSegmentFromAddress(absAddr)->getName() == refedName)
	{
		_solvedRefs[refAddr] = std::make_pair(absAddr, "");
		// ok
	}
	else if (_image->getImage()->getSegmentFromAddress(absAddr)
			&& _image->getImage()->getSegmentFromAddress(absAddr)->getSecSeg()
			&& _image->getImage()->getSegmentFromAddress(absAddr)->getSecSeg()->getType() == fileformat::SecSeg::Type::BSS)
	{
		_solvedRefs[refAddr] = std::make_pair(absAddr, refedName);
		// ok
	}
	// Image base can be referenced.
	//
	else if (absAddr == _image->getImage()->getBaseAddress()
			&& refedName == "__image_base__")
	{
		_solvedRefs[refAddr] = std::make_pair(absAddr, "");
		// ok
	}
	else if (_image->getImage()->getSegmentFromAddress(absAddr)
			&& _image->getImage()->getSegmentFromAddress(absAddr)->getSecSeg()
			&& (_image->getImage()->getSegmentFromAddress(absAddr)->getSecSeg()->getType() == fileformat::SecSeg::Type::DATA
					|| _image->getImage()->getSegmentFromAddress(absAddr)->getSecSeg()->getType() == fileformat::SecSeg::Type::CONST_DATA))
	{
		_solvedRefs[refAddr] = std::make_pair(absAddr, refedName);
		// ok
	}
	// Relative address of detected function.
	//
	else if (relCdIt != _confirmedDetections.end()
			&& hasItem(relCdIt->second.names, refedName))
	{
		_solvedRefs[refAddr] = std::make_pair(relAddr, refedName);
		// ok
	}
	// Relative address of imported function.
	//
	else if (_imports.count(relAddr)
			&& _imports[relAddr] == refedName)
	{
		_solvedRefs[refAddr] = std::make_pair(relAddr, refedName);
		// ok
	}
	// Relative address of data in named section.
	//
	else if (_image->getImage()->getSegmentFromAddress(relAddr)
			&& _image->getImage()->getSegmentFromAddress(relAddr)->getName() == refedName)
	{
		_solvedRefs[refAddr] = std::make_pair(relAddr, "");
		// ok
	}
	else if (_image->getConstantDefault(relAddr+2)
			&& _imports.count(_image->getConstantDefault(relAddr+2)->getZExtValue()))
	{
		_solvedRefs[refAddr] = std::make_pair(relAddr, refedName);
		// ok
	}
	else
	{
		allRefsOk = false;
		break;
	}
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

utils::Address getAddressFromRef_x86(utils::Address ref)
{

}

} // namespace bin2llvmir
} // namespace retdec
