/**
* @file include/retdec/bin2llvmir/optimizations/decoder/names.h
* @brief Database of objects' names in binary.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_NAMES_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_NAMES_H

#include <map>
#include <set>

#include "retdec/utils/address.h"

namespace retdec {
namespace bin2llvmir {

/**
 * Representation of one name.
 */
class Name
{
	public:
		/**
		 * Name type and its priority.
		 * Lower number -> higher priority.
		 */
		enum class eType
		{
			EP,
			INVALID,
		};

	public:
		Name();
		Name(const std::string& name, eType type);

		operator std::string() const;
		explicit operator bool() const;
		bool operator<(const Name& o) const;

		const std::string& getName() const;
		eType getType() const;

	private:
		std::string _name;
		eType _type = eType::INVALID;
};

/**
 * Representation of all the names for one object.
 */
class Names
{
	public:
		using iterator = typename std::set<Name>::iterator;

	public:
		void addName(const std::string& name, Name::eType type);

		const Name& getPreferredName();

		iterator begin();
		iterator end();
		std::size_t size() const;
		bool empty() const;

	private:
		std::set<Name> _names;
		static Name _emptyName;
};

/**
 * Names container.
 */
class NameContainer
{
	public:
		void addNameForAddress(
				retdec::utils::Address a,
				const std::string& name,
				Name::eType type);

		const Names& getNamesForAddress(retdec::utils::Address a);
		const Name& getPreferredNameForAddress(retdec::utils::Address a);

	private:
		std::map<retdec::utils::Address, Names> _data;
		static Names _emptyNames;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
