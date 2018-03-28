/**
* @file src/bin2llvmir/optimizations/decoder/jump_targets.cpp
* @brief Jump targets representation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/jump_targets.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"

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
		retdec::utils::Address f)
		:
		_address(a),
		_type(t),
		_fromAddress(f),
		_mode(m)
{

}

bool JumpTarget::operator<(const JumpTarget& o) const
{
	if (getType() == o.getType())
	{
		if (getAddress() == o.getAddress())
		{
			return getFromAddress() < o.getFromAddress();
		}
		else
		{
			return getAddress() < o.getAddress();
		}
	}
	else
	{
		return getType() < o.getType();
	}
}

retdec::utils::Address JumpTarget::getAddress() const
{
	return _address;
}

JumpTarget::eType JumpTarget::getType() const
{
	return _type;
}

retdec::utils::Address JumpTarget::getFromAddress() const
{
	return _fromAddress;
}

std::ostream& operator<<(std::ostream &out, const JumpTarget& jt)
{
	std::string t;
	switch (jt.getType())
	{
		case JumpTarget::eType::CONTROL_FLOW_BR_FALSE:
			t = "CONTROL_FLOW_BR_FALSE";
			break;
		case JumpTarget::eType::CONTROL_FLOW_BR_TRUE:
			t = "CONTROL_FLOW_BR_TRUE";
			break;
		case JumpTarget::eType::CONTROL_FLOW_SWITCH_CASE:
			t = "CONTROL_FLOW_SWITCH_CASE";
			break;
		case JumpTarget::eType::CONTROL_FLOW_CALL_TARGET:
			t = "CONTROL_FLOW_CALL_TARGET";
			break;
		case JumpTarget::eType::CONTROL_FLOW_RETURN_TARGET:
			t = "CONTROL_FLOW_RETURN_TARGET";
			break;
		case JumpTarget::eType::CONFIG:
			t = "CONFIG";
			break;
		case JumpTarget::eType::ENTRY_POINT:
			t = "ENTRY_POINT";
			break;
		case JumpTarget::eType::EXPORT:
			t = "EXPORT";
			break;
		case JumpTarget::eType::DEBUG:
			t = "DEBUG";
			break;
		case JumpTarget::eType::SYMBOL_PUBLIC:
			t = "SYMBOL_PUBLIC";
			break;
		case JumpTarget::eType::SYMBOL:
			t = "SYMBOL";
			break;
		case JumpTarget::eType::LEFTOVER:
			t = "LEFTOVER";
			break;
		default:
			assert(false && "unknown type");
			t = "unknown";
			break;
	}

	out << jt.getAddress() << " (" << t << ")";
	if (jt.getFromAddress().isDefined())
	{
		out << ", from = " << jt.getFromAddress();
	}
	return out;
}

//
//==============================================================================
// JumpTargets
//==============================================================================
//

void JumpTargets::push(
		retdec::utils::Address a,
		JumpTarget::eType t,
		cs_mode m,
		retdec::utils::Address f)
{
	if (a.isDefined())
	{
		_data.insert(JumpTarget(a, t, m, f));
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
	_data.erase(top());
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
