/**
 * @file src/llvm-support/utils.cpp
 * @brief LLVM Utility functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>

#include <llvm/IR/CFG.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>

#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/utils.h"
#include "retdec/utils/address.h"
#include "retdec/utils/string.h"

using namespace retdec::utils;

namespace retdec {
namespace bin2llvmir {

/**
 * We need special function for @c Module printing because
 * its @c print method takes one more parameter.
 * @param t Module to print.
 * @return String with printed module.
 */
std::string llvmObjToString(const llvm::Module* t)
{
	std::string str;
	llvm::raw_string_ostream ss(str);
	if (t)
		t->print(ss, nullptr);
	else
		ss << "nullptr";
	return ss.str();
}
std::string llvmObjToString(const llvm::Module& t)
{
	return llvmObjToString(&t);
}

void dumpModuleToFile(const llvm::Module* m, const std::string fileName)
{
	static unsigned cntr = 0;
	std::string n = fileName.empty()
			? "dump_" + std::to_string(cntr++) + ".ll"
			: fileName;

	std::ofstream myfile(n);
	myfile << llvmObjToString(m) << std::endl;
}

/**
 * Skips both casts and getelementptr instructions and constant expressions.
 */
llvm::Value* skipCasts(llvm::Value* val)
{
	while (true)
	{
		if (auto* c = llvm::dyn_cast_or_null<llvm::CastInst>(val))
		{
			val = c->getOperand(0);
		}
		else if (auto* p = llvm::dyn_cast_or_null<llvm::GetElementPtrInst>(val))
		{
			val = p->getOperand(0);
		}
		else if (auto* ce = llvm::dyn_cast_or_null<llvm::ConstantExpr>(val))
		{
			if (ce->isCast()
					|| ce->getOpcode() == llvm::Instruction::GetElementPtr)
			{
				val = ce->getOperand(0);
			}
			else
			{
				return val;
			}
		}
		else
		{
			return val;
		}
	}

	return val;
}

//
//==============================================================================
// Control flow to JSON serialization.
//==============================================================================
//

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

retdec::utils::Address getFunctionAddress(llvm::Function* f)
{
	if (f == nullptr)
	{
		return Address();
	}

	AsmInstruction ai(f);
	return ai.isValid() ? ai.getAddress() : Address();
}

retdec::utils::Address getFunctionEndAddress(llvm::Function* f)
{
	if (f == nullptr)
	{
		return Address();
	}

	if (f->empty() || f->back().empty())
	{
		return getFunctionAddress(f);
	}

	AsmInstruction ai(&f->back().back());
	return ai.isValid() ? ai.getEndAddress() : getFunctionAddress(f);
}

retdec::utils::Address getBasicBlockAddressFromName(llvm::BasicBlock* b)
{
	if (b == nullptr)
	{
		return Address();
	}

	std::string n = b->getName();

	unsigned long long a = 0;
	int ret = std::sscanf(n.c_str(), "bb_%llx", &a);
	return ret == 1 ? Address(a) : Address();
}

retdec::utils::Address getBasicBlockAddress(llvm::BasicBlock* b)
{
	if (b == nullptr)
	{
		return Address();
	}

	std::string n = b->getName();
	if (!retdec::utils::startsWith(n, "bb_"))
	{
		return Address();
	}

	if (b->empty())
	{
		return getBasicBlockAddressFromName(b);
	}

	AsmInstruction ai(&b->front());
	return ai.isValid() ? ai.getAddress() : getBasicBlockAddressFromName(b);
}

retdec::utils::Address getBasicBlockEndAddress(llvm::BasicBlock* b)
{
	if (b == nullptr)
	{
		return Address();
	}

	if (b->empty())
	{
		return getBasicBlockAddress(b);
	}

	AsmInstruction ai(&b->back());
	return ai.isValid() ? ai.getEndAddress() : getBasicBlockAddress(b);
}

void dumpControFlowToJsonBasicBlock(
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

void dumpControFlowToJsonFunction(
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
		for (llvm::BasicBlock& bb : f)
		{
			// There are more BBs in LLVM IR than we created in control-flow
			// decoding - e.g. BBs inside instructions that behave like
			// if-then-else created by capstone2llvmir.
			if (getBasicBlockAddress(&bb).isUndefined())
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

			llvm::BasicBlock* bbEnd = &bb;
			while (bbEnd->getNextNode())
			{
				// Next has address -- is a proper BB.
				//
				if (getBasicBlockAddress(bbEnd->getNextNode()).isDefined())
				{
					break;
				}
				else
				{
					bbEnd = bbEnd->getNextNode();
				}
			}

			dumpControFlowToJsonBasicBlock(bb, *bbEnd, out);
		}
		out << "\n";

		out << genIndent(2) << "]," << "\n";
	}

	std::set<Address> usersAddrs; // sort addresses
	for (auto* u : f.users())
	{
		if (auto* i = llvm::dyn_cast<llvm::Instruction>(u))
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

} // anonymous namespace

void dumpControFlowToJson(
		llvm::Module* m,
		const std::string& fileName)
{
	std::ofstream json(fileName);
	if (!json.is_open())
	{
		return;
	}

	json << "[\n";

	bool first = true;
	for (llvm::Function& f : m->functions())
	{
		if (f.isDeclaration())
		{
			continue;
		}

		// There are some temp and utility fncs that do not have addresses.
		if (getFunctionAddress(&f).isUndefined())
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

		dumpControFlowToJsonFunction(f, json);
	}
	json << "\n";

	json << "]";
}

} // namespace bin2llvmir
} // namespace retdec
