/**
* @file src/bin2llvmir/optimizations/decoder/decode_ranges.h
* @brief Representation of ranges to decode.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder_ranges.h"

using namespace retdec::utils;

namespace {

inline retdec::utils::Address align(
		const retdec::utils::Address& s,
		unsigned a)
{
	return a && s % a ? retdec::utils::Address(s + a - (s % a)) : s;
}

} // namespace anonymous

namespace retdec {
namespace bin2llvmir {

void RangesToDecode::addPrimary(utils::Address s, utils::Address e)
{
	s = align(s, archInsnAlign);
	_primaryRanges.insert(s, e);
}

void RangesToDecode::addPrimary(const utils::AddressRange& r)
{
	addPrimary(r.getStart(), r.getEnd());
}

void RangesToDecode::addAlternative(utils::Address s, utils::Address e)
{
	s = align(s, archInsnAlign);
	_alternativeRanges.insert(s, e);
}

void RangesToDecode::addAlternative(const utils::AddressRange& r)
{
	addAlternative(r.getStart(), r.getEnd());
}

void RangesToDecode::remove(utils::Address s, utils::Address e)
{
	e = align(e + 1, archInsnAlign) - 1;
	_primaryRanges.remove(s, e);
	_alternativeRanges.remove(s, e);
}

void RangesToDecode::remove(const utils::AddressRange& r)
{
	remove(r.getStart(), r.getEnd());
}

bool RangesToDecode::primaryEmpty() const
{
	return _primaryRanges.empty();
}

bool RangesToDecode::alternativeEmpty() const
{
	return _alternativeRanges.empty();
}

const utils::AddressRange& RangesToDecode::primaryFront() const
{
	return *_primaryRanges.begin();
}

const utils::AddressRange& RangesToDecode::alternativeFront() const
{
	return *_alternativeRanges.begin();
}

const utils::AddressRange* RangesToDecode::getPrimary(utils::Address a) const
{
	return _primaryRanges.getRange(a);
}

const utils::AddressRange* RangesToDecode::getAlternative(
		utils::Address a) const
{
	return _alternativeRanges.getRange(a);
}

const utils::AddressRange* RangesToDecode::get(utils::Address a) const
{
	auto* p = getPrimary(a);
	return p ? p : getAlternative(a);
}

void RangesToDecode::setArchitectureInstructionAlignment(unsigned a)
{
	archInsnAlign = a;
}

std::ostream& operator<<(std::ostream &os, const RangesToDecode& rs)
{
	os << "Primary ranges:" << std::endl;
	os << rs._primaryRanges << std::endl;
	os << "Alternative ranges:" << std::endl;
	os << rs._alternativeRanges << std::endl;
	return os;
}

} // namespace bin2llvmir
} // namespace retdec
