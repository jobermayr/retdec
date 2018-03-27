/**
* @file src/bin2llvmir/optimizations/decoder/names.cpp
* @brief Database of objects' names in binary.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/names.h"

using namespace retdec::utils;

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// Name
//==============================================================================
//

Name::Name()
{

}

Name::Name(const std::string& name, eType type) :
		_name(name),
		_type(type)
{

}

Name::operator std::string() const
{
	return _name;
}

Name::operator bool() const
{
	return _type != eType::INVALID;
}

bool Name::operator<(const Name& o) const
{
	if (_type == o._type)
	{
		return _name < o._name;
	}
	else
	{
		return _type < o._type;
	}
}

const std::string& Name::getName() const
{
	return _name;
}

Name::eType Name::getType() const
{
	return _type;
}

//
//==============================================================================
// Names
//==============================================================================
//

Name Names::_emptyName;

void Names::addName(const std::string& name, Name::eType type)
{
	_names.emplace(name, type);
}

const Name& Names::getPreferredName()
{
	return _names.empty() ? _emptyName : *_names.begin();
}

Names::iterator Names::begin()
{
	return _names.begin();
}

Names::iterator Names::end()
{
	return _names.end();
}

std::size_t Names::size() const
{
	return _names.size();
}

bool Names::empty() const
{
	return _names.empty();
}

//
//==============================================================================
// NameContainer
//==============================================================================
//

Names NameContainer::_emptyNames;

void NameContainer::addNameForAddress(
		retdec::utils::Address a,
		const std::string& name,
		Name::eType type)
{
	auto& ns = _data[a];
	ns.addName(name, type);
}

const Names& NameContainer::getNamesForAddress(retdec::utils::Address a)
{
	auto it = _data.find(a);
	return it != _data.end() ? it->second : _emptyNames;
}

const Name& NameContainer::getPreferredNameForAddress(retdec::utils::Address a)
{
	auto it = _data.find(a);
	return it != _data.end()
			? it->second.getPreferredName()
			: _emptyNames.getPreferredName();
}

} // namespace bin2llvmir
} // namespace retdec
