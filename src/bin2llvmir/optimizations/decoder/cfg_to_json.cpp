/**
* @file src/bin2llvmir/optimizations/decoder/cfg_to_json.cpp
* @brief Dump control flow to JSON.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* Dump the decoded LLVM module's control flow to file in JSON format that
* can be diffed with control flow dump from other tools (e.g. IDA, avast
* disassembler).
* We create JSON manually to make sure it is formated exactly as expected.
* When JsonCpp is used the formatting is different than JSON generated in
* Python. I was unable to force either json library, or python json library,
* to produce the same formatting as the other library.
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"

using namespace retdec::utils;
using namespace retdec::capstone2llvmir;
using namespace llvm;
using namespace retdec::fileformat;

namespace {

std::string genIndent(unsigned level = 1, unsigned perLevel = 4, char c = ' ')
{
	std::string indent(perLevel, c);
	std::string ret;
	for (unsigned i = 0; i < level; ++i)
	{
		ret += indent;
	}
	return ret;
}

std::string genJsonLine(const std::string& name, const std::string& val)
{
	return "\"" + name + "\": " + "\"" + val + "\",";
}

} // anonymous namespace

namespace retdec {
namespace bin2llvmir {

void Decoder::dumpControFlowToJsonModule_manual()
{
	std::ofstream json("control-flow.json");
	if (!json.is_open())
	{
		return;
	}

	json << "[\n";

	bool first = true;
	for (llvm::Function& f : _module->functions())
	{
		if (f.isDeclaration())
		{
			continue;
		}

		// There are some temp and utility fncs that do not have addresses.
		if (_fnc2addr.count(&f) == 0)
		{
			continue;
		}

		if (first)
		{
			first = false;
		}
		else
		{
			json << ",\n";
		}

		dumpControFlowToJsonFunction_manual(f, json);
	}
	json << "\n";

	json << "]";
}

void Decoder::dumpControFlowToJsonFunction_manual(
		llvm::Function& f,
		std::ostream &out)
{
	auto start = getFunctionAddress(&f);
	auto end = getFunctionEndAddress(&f);

	out << genIndent(1) << "{\n";
	out << genIndent(2) << genJsonLine("address", start.toHexPrefixString()) << "\n";
	out << genIndent(2) << genJsonLine("address_end", end.toHexPrefixString()) << "\n";
	if (f.empty())
	{
		out << genIndent(2) << "\"bbs\": []" << "\n";
	}
	else
	{
		out << genIndent(2) << "\"bbs\": [" << "\n";

		bool first = true;
		for (BasicBlock& bb : f)
		{
			// There are more BBs in LLVM IR than we created in control-flow
			// decoding - e.g. BBs inside instructions that behave like
			// if-then-else created by capstone2llvmir.
			if (_bb2addr.count(&bb) == 0)
			{
				continue;
			}

			if (first)
			{
				first = false;
			}
			else
			{
				out << ",\n";
			}

			BasicBlock* bbEnd = &bb;
			while (bbEnd->getNextNode())
			{
				// Next has address -- is a proper BB.
				//
				if (_bb2addr.count(bbEnd->getNextNode()))
				{
					break;
				}
				else
				{
					bbEnd = bbEnd->getNextNode();
				}
			}

			dumpControFlowToJsonBasicBlock_manual(bb, *bbEnd, out);
		}
		out << "\n";

		out << genIndent(2) << "]," << "\n";
	}

	std::set<Address> usersAddrs; // sort addresses
	for (auto* u : f.users())
	{
		if (auto* i = llvm::dyn_cast<Instruction>(u))
		{
			if (auto ai = AsmInstruction(i))
			{
				usersAddrs.insert(ai.getAddress());
			}
		}
	}

	if (usersAddrs.empty())
	{
		out << genIndent(2) << "\"code_refs\": []" << "\n";
	}
	else
	{
		out << genIndent(2) << "\"code_refs\": [" << "\n";

		bool first = true;
		for (auto& r : usersAddrs)
		{
			if (first)
			{
				first = false;
			}
			else
			{
				out << ",\n";
			}
			out << genIndent(3) << "\"" << r.toHexPrefixString() << "\"";
		}
		out << "\n";

		out << genIndent(2) << "]" << "\n";
	}

	out << genIndent(1) << "}";
}

void Decoder::dumpControFlowToJsonBasicBlock_manual(
		llvm::BasicBlock& bb,
		llvm::BasicBlock& bbEnd,
		std::ostream &out)
{
	auto start = getBasicBlockAddress(&bb);
	auto end = getBasicBlockEndAddress(&bbEnd);

	out << genIndent(3) << "{" << "\n";
	out << genIndent(4) << genJsonLine("address", start.toHexPrefixString()) << "\n";
	out << genIndent(4) << genJsonLine("address_end", end.toHexPrefixString()) << "\n";

	std::set<Address> predsAddrs; // sort addresses
	for (auto pit = pred_begin(&bb), e = pred_end(&bb); pit != e; ++pit)
	{
		// Find BB with address - there should always be some.
		// Some BBs may not have addresses - e.g. those inside
		// if-then-else instruction models.
		auto* pred = *pit;
		auto start = getBasicBlockAddress(pred);
		while (start.isUndefined())
		{
			pred = pred->getPrevNode();
			assert(pred);
			start = getBasicBlockAddress(pred);
		}
		predsAddrs.insert(start);
	}

	if (predsAddrs.empty())
	{
		out << genIndent(4) << "\"preds\": []," << "\n";
	}
	else
	{
		bool first = true;
		out << genIndent(4) << "\"preds\": [" << "\n";
		for (auto pred : predsAddrs)
		{
			if (first)
			{
				first = false;
			}
			else
			{
				out << ",\n";
			}
			out << genIndent(5) << "\"" << pred.toHexPrefixString() << "\"";
		}
		out << "\n";
		out << genIndent(4) << "]," << "\n";
	}

	std::set<Address> succsAddrs; // sort addresses
	for (auto sit = succ_begin(&bbEnd), e = succ_end(&bbEnd); sit != e; ++sit)
	{
		// Find BB with address - there should always be some.
		// Some BBs may not have addresses - e.g. those inside
		// if-then-else instruction models.
		auto* succ = *sit;
		auto start = getBasicBlockAddress(succ);
		while (start.isUndefined())
		{
			succ = succ->getPrevNode();
			assert(succ);
			start = getBasicBlockAddress(succ);
		}
		succsAddrs.insert(start);
	}

	if (succsAddrs.empty())
	{
		out << genIndent(4) << "\"succs\": []" << "\n";
	}
	else
	{
		bool first = true;
		out << genIndent(4) << "\"succs\": [" << "\n";
		for (auto succ : succsAddrs)
		{
			if (first)
			{
				first = false;
			}
			else
			{
				out << ",\n";
			}
			out << genIndent(5) << "\"" << succ.toHexPrefixString() << "\"";
		}
		out << "\n";
		out << genIndent(4) << "]" << "\n";
	}

	out << genIndent(3) << "}";
}

} // namespace bin2llvmir
} // namespace retdec
