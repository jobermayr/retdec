/**
* @file src/bin2llvmir/optimizations/decoder/jump_targets.cpp
* @brief Jump targets representation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/jump_targets.h"

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// JumpTarget
//==============================================================================
//

JumpTarget::JumpTarget()
{

}

JumpTarget::JumpTarget(
		retdec::utils::Address a,
		eType t,
		cs_mode m,
		retdec::utils::Address f,
		const std::string& n)
		:
		address(a),
		fromAddress(f),
		type(t),
		_mode(m),
		_name(n)
{

}

JumpTarget::JumpTarget(
		retdec::utils::Address a,
		eType t,
		cs_mode m,
		llvm::Instruction* f,
		const std::string& n)
		:
		address(a),
		fromInst(f),
		type(t),
		_mode(m),
		_name(n)
{

}

bool JumpTarget::operator<(const JumpTarget& o) const
{
	if (type == o.type)
	{
		return address < o.address;
	}
	else
	{
		return type < o.type;
	}
}

bool JumpTarget::createFunction() const
{
	return type == eType::ENTRY_POINT
			|| type == eType::CONTROL_FLOW_CALL_TARGET
			;
}

bool JumpTarget::doDryRun() const
{
	return type == eType::CONTROL_FLOW_CALL_AFTER
			;
}

bool JumpTarget::hasName() const
{
	return !_name.empty();
}

std::string JumpTarget::getName() const
{
	return _name;
}

bool JumpTarget::isKnownMode() const
{
	return !isUnknownMode();
}

bool JumpTarget::isUnknownMode() const
{
	return _mode == CS_MODE_BIG_ENDIAN;
}

std::ostream& operator<<(std::ostream &out, const JumpTarget& jt)
{
	std::string t;
	switch (jt.type)
	{
		case JumpTarget::eType::ENTRY_POINT:
			t = "ENTRY_POINT";
			break;
		case JumpTarget::eType::CONTROL_FLOW_BR_FALSE:
			t = "CONTROL_FLOW_BR_FALSE";
			break;
		case JumpTarget::eType::CONTROL_FLOW_BR_TRUE:
			t = "CONTROL_FLOW_BR_TRUE";
			break;
		case JumpTarget::eType::CONTROL_FLOW_CALL_AFTER:
			t = "CONTROL_FLOW_CALL_AFTER";
			break;
		case JumpTarget::eType::CONTROL_FLOW_CALL_TARGET:
			t = "CONTROL_FLOW_CALL_TARGET";
			break;
		case JumpTarget::eType::CONTROL_FLOW_RETURN_TARGET:
			t = "CONTROL_FLOW_RETURN_TARGET";
			break;
		default:
			assert(false && "unknown type");
			t = "unknown";
			break;
	}

	out << jt.address << " (" << t << ")";
	if (jt.hasName())
	{
		out << ", name = " << jt.getName();
	}
	return out;
}

//
//==============================================================================
// JumpTargets
//==============================================================================
//

void JumpTargets::push(const JumpTarget& jt)
{
	if (jt.address.isDefined())
	{
		_data.insert(jt);
	}
}

void JumpTargets::push(
		retdec::utils::Address a,
		JumpTarget::eType t,
		cs_mode m,
		retdec::utils::Address f,
		const std::string& n)
{
	if (a.isDefined())
	{
		_data.insert(JumpTarget(a, t, m, f, n));
	}
}

void JumpTargets::push(
		retdec::utils::Address a,
		JumpTarget::eType t,
		cs_mode m,
		llvm::Instruction* f,
		const std::string& n)
{
	if (a.isDefined())
	{
		_data.insert(JumpTarget(a, t, m, f, n));
	}
}

std::size_t JumpTargets::size() const
{
	return _data.size();
}

void JumpTargets::clear()
{
	_data.clear();
}

bool JumpTargets::empty()
{
	return _data.empty();
}

const JumpTarget& JumpTargets::top()
{
	return *_data.begin();
}

void JumpTargets::pop()
{
	_poped.insert(top().address);
	_data.erase(top());
}

bool JumpTargets::wasAlreadyPoped(JumpTarget& ct) const
{
	return _poped.count(ct.address);
}

auto JumpTargets::begin()
{
	return _data.begin();
}

auto JumpTargets::end()
{
	return _data.end();
}

std::ostream& operator<<(std::ostream &out, const JumpTargets& jts)
{
	for (auto& jt : jts._data)
	{
		out << jt << std::endl;
	}
	return out;
}

} // namespace bin2llvmir
} // namespace retdec
