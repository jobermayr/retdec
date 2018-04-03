/**
* @file src/bin2llvmir/optimizations/decoder/static_code.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iostream>

#include "retdec/utils/container.h"
#include "retdec/utils/filesystem_path.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/stacofin/stacofin.h"

using namespace retdec::utils;
using namespace retdec::stacofin;

namespace {

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
		}
	}
}

std::set<std::string> selectSignaturePaths(FileImage* image, Config* config)
{
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
			selectSignaturesWithNames(allSigs, sigs, {"psp-gcc-4.3.5"}, {"pic32", "uClibc"});
		}
		else if (c.tools.isPic32()
				&& c.tools.isTool("4.5.2"))
		{
			selectSignaturesWithNames(allSigs, sigs, {"pic32-gcc-4.5.2"}, {"psp", "uClibc"});
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
				selectSignaturesWithNames(allSigs, sigs, {"gcc-4.8.3"}, {"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.7.2"))
			{
				selectSignaturesWithNames(allSigs, sigs, {"gcc-4.7.2"}, {"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.4.1"))
			{
				selectSignaturesWithNames(allSigs, sigs, {"gcc-4.4.1"}, {"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.5.2"))
			{
				selectSignaturesWithNames(allSigs, sigs, {"gcc-4.5.2"}, {"psp", "pic32", "uClibc"});
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

} // namespace anonymous

namespace retdec {
namespace bin2llvmir {

void Decoder::initStaticCode()
{
	LOG << "\n initStaticCode():" << std::endl;

	std::set<std::string> sigPaths = selectSignaturePaths(_image, _config);
	LOG << "\tSelected signatures:" << std::endl;
	for (auto& p : sigPaths)
	{
		LOG << "\t\t" << p << std::endl;
	}

	Finder codeFinder;
	for (const auto &path : sigPaths)
	{
		codeFinder.search(*_image->getImage(), path);
	}

	LOG << "\tDetected functions:" << std::endl;
	for (auto& f : codeFinder.accessDectedFunctions())
	{
		std::string n = f.names.front();

		LOG << "\t\t" << f.address << " @ " << n << ", sz = " << f.size
				<< std::endl;

		for (auto& p : f.references)
		{
			Address refAddr = f.address + p.first;

			LOG << "\t\t\t" << refAddr << " @ " << p.second;

			uint64_t val = 0;
			if (_image->getImage()->getWord(refAddr, val))
			{
				LOG << ", val = " << val;
			}

			LOG << std::endl;
		}
	}

//=============================================================================

	std::map<Address, stacofin::DetectedFunction> confirmedDetections;
	std::list<stacofin::DetectedFunction> worklistDetections;

	for (auto& f : codeFinder.accessDectedFunctions())
	{
		worklistDetections.push_back(f);
	}

Address logAddr = 0x401d00;

LOG << "\tChecking detected functions:" << std::endl;

	bool changed = true;
	while (changed && !worklistDetections.empty())
	{
		changed = false;

		for (auto wIt = worklistDetections.begin(), e = worklistDetections.end(); wIt != e;)
		{
			auto& f = *wIt;

if (logAddr == f.address) LOG << "\t\t" << f.names.front() << " @ " << f.address << std::endl;

			bool allRefsOk = true;
			for (auto& p : f.references)
			{
				Address refAddr = f.address + p.first;
				std::string& refedName = p.second;

				uint64_t val = 0;
				if (!_image->getImage()->getWord(refAddr, val))
				{
					allRefsOk = false;
					break;
				}

				Address absAddr = val;
				Address addrAfterRef = refAddr + _image->getImage()->getBytesPerWord();
				Address relAddr = addrAfterRef + int32_t(val); // TODO: arch size specific

				auto absCdIt = confirmedDetections.find(absAddr);
				auto relCdIt = confirmedDetections.find(relAddr);

if (logAddr == f.address) LOG << "\t\t\tref = " << refedName << " @ " << refAddr << ", abs = " << absAddr << ", rel = " << relAddr << " (" << addrAfterRef << " + " << int32_t(val) << ")" << std::endl;

				// Absolute address of detected function.
				//
				if (absCdIt != confirmedDetections.end()
						&& hasItem(absCdIt->second.names, refedName))
				{
if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #1" << std::endl;
					// ok
				}
				// Absolute address of imported function.
				//
				else if (_imports.count(absAddr)
						&& _imports[absAddr] == refedName)
				{
if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #2" << std::endl;
					// ok
				}
				// Absolute address of data in named section.
				//
				else if (_image->getImage()->getSegmentFromAddress(absAddr)
						&& _image->getImage()->getSegmentFromAddress(absAddr)->getName() == refedName)
				{
if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #3" << std::endl;
					// ok
				}
				else if (_image->getImage()->getSegmentFromAddress(absAddr)
						&& _image->getImage()->getSegmentFromAddress(absAddr)->getSecSeg()
						&& _image->getImage()->getSegmentFromAddress(absAddr)->getSecSeg()->getType() == fileformat::SecSeg::Type::BSS)
				{
if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #3.5" << std::endl;
					// ok
				}
				// Image base can be referenced.
				//
				else if (absAddr == _image->getImage()->getBaseAddress()
						&& refedName == "__image_base__")
				{
if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #3.6" << std::endl;
					// ok
				}
				else if (_image->getImage()->getSegmentFromAddress(absAddr)
						&& _image->getImage()->getSegmentFromAddress(absAddr)->getSecSeg()
						&& (_image->getImage()->getSegmentFromAddress(absAddr)->getSecSeg()->getType() == fileformat::SecSeg::Type::DATA
								|| _image->getImage()->getSegmentFromAddress(absAddr)->getSecSeg()->getType() == fileformat::SecSeg::Type::CONST_DATA))
				{
if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #3.5" << std::endl;
					// ok
				}
				// Relative address of detected function.
				//
				else if (relCdIt != confirmedDetections.end()
						&& hasItem(relCdIt->second.names, refedName))
				{
if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #4" << std::endl;
					// ok
				}
				// Relative address of imported function.
				//
				else if (_imports.count(relAddr)
						&& _imports[relAddr] == refedName)
				{
if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #5" << std::endl;
					// ok
				}
				// Relative address of data in named section.
				//
				else if (_image->getImage()->getSegmentFromAddress(relAddr)
						&& _image->getImage()->getSegmentFromAddress(relAddr)->getName() == refedName)
				{
if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #6" << std::endl;
					// ok
				}
				else if (_image->getConstantDefault(relAddr+2)
						&& _imports.count(_image->getConstantDefault(relAddr+2)->getZExtValue()))
//					)
				{
//if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #7 - " << Address(_image->getConstantDefault(relAddr+2)->getZExtValue()) << std::endl;
if (logAddr == f.address) LOG << "\t\t\t\t" << "ok #7" << std::endl;
					// ok
				}
				else
				{
if (logAddr == f.address) LOG << "\t\t\t\t" << "fail #1" << std::endl;
					allRefsOk = false;
					break;
				}
			}

			if (allRefsOk)
			{
				confirmedDetections.emplace(f.address, f);
				wIt = worklistDetections.erase(wIt);
				changed = true;
			}
			else
			{
				++wIt;
			}
		}
	}

	changed = true;
	while (changed && !worklistDetections.empty())
	{
		changed = false;
	}

	LOG << "\tConfirmed functions:" << std::endl;
	for (auto& p : confirmedDetections)
	{
		LOG << "\t\t" << p.first << " @ " << p.second.names.front() << std::endl;
	}
	LOG << "\tUn-confirmed functions:" << std::endl;
	for (auto& f : worklistDetections)
	{
		LOG << "\t\t" << f.address << " @ " << f.names.front() << std::endl;
	}

	exit(1);
}

} // namespace bin2llvmir
} // namespace retdec
