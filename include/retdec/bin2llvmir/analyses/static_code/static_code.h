/**
* @file include/retdec/bin2llvmir/analyses/static_code/static_code.h
* @brief Static code analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_STATIC_CODE_STATIC_CODE_H
#define RETDEC_BIN2LLVMIR_ANALYSES_STATIC_CODE_STATIC_CODE_H

#include <map>

#include <capstone/capstone.h>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/stacofin/stacofin.h"
#include "retdec/utils/address.h"

namespace retdec {
namespace bin2llvmir {

class StaticCodeFunction
{
	public:
		class Reference
		{
			public:
				Reference(
						std::size_t o,
						utils::Address a,
						const std::string& n,
						utils::Address t = utils::Address::getUndef,
						StaticCodeFunction* tf = nullptr,
						bool k = false);

			public:
				std::size_t offset = 0;
				utils::Address address;
				std::string name;

				utils::Address target;
				StaticCodeFunction* targetFnc = nullptr;
				bool ok = false;
		};

	public:
		StaticCodeFunction(const stacofin::DetectedFunction& df);
		bool allRefsOk() const;

	public:
		utils::Address address;
		std::size_t size;
		std::vector<std::string> names;
		std::string signaturePath;

		std::vector<Reference> references;
};

class StaticCodeAnalysis
{
	public:
		using DetectedFunctionsMap = typename std::map<
				utils::Address,
				StaticCodeFunction*>;
		using DetectedFunctionsMultimap = typename std::multimap<
				utils::Address,
				StaticCodeFunction>;

	public:
		StaticCodeAnalysis(Config* c, FileImage* i, csh ce);
		~StaticCodeAnalysis();

		const DetectedFunctionsMultimap& getAllDetections() const;
		const DetectedFunctionsMap& getConfirmedDetections() const;

	private:
		void solveReferences();

		utils::Address getAddressFromRef(utils::Address ref);
		utils::Address getAddressFromRef_x86(utils::Address ref);

		void checkRef(StaticCodeFunction::Reference& ref);
		void checkRef_x86(StaticCodeFunction::Reference& ref);

	private:
		Config* _config = nullptr;
		FileImage* _image = nullptr;

		csh _ce;
		cs_insn* _ceInsn = nullptr;

		stacofin::Finder _codeFinder;

		std::set<std::string> _sigPaths;
		std::map<utils::Address, std::string> _imports;

		DetectedFunctionsMultimap _allDetections;
		DetectedFunctionsMap _confirmedDetections;

//		std::map<utils::Address, utils::Address> _solvedRefs;
//		std::map<utils::Address, std::pair<utils::Address, std::string>> _solvedRefs;
//		DetectedFunctionsMultimap _allDetections;
//		DetectedFunctionsMultimap _worklistDetections;
//		DetectedFunctionsMultimap _rerectedDetections;
};

} // namespace bin2llvmir
} // namespace retdec

#endif