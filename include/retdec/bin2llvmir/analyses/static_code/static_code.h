/**
* @file include/retdec/bin2llvmir/analyses/static_code/static_code.h
* @brief Static code analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_STATIC_CODE_STATIC_CODE_H
#define RETDEC_BIN2LLVMIR_ANALYSES_STATIC_CODE_STATIC_CODE_H

#include <map>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/stacofin/stacofin.h"
#include "retdec/utils/address.h"

namespace retdec {
namespace bin2llvmir {

class StaticCodeAnalysis
{
	public:
		using DetectedFunctionsMap = typename std::map<
				utils::Address,
				stacofin::DetectedFunction>;
		using DetectedFunctionsMultimap = typename std::multimap<
				utils::Address,
				stacofin::DetectedFunction>;

	public:
		StaticCodeAnalysis(Config* c, FileImage* i);

		const DetectedFunctionsMultimap& getAllDetections() const;
		const DetectedFunctionsMap& getConfirmedDetections() const;

	private:
		void strictSolve();

		bool checkRef(utils::Address ref, const std::string& name);

		utils::Address getAddressFromRef(utils::Address ref);
		utils::Address getAddressFromRef_x86(utils::Address ref);

	private:
		Config* _config = nullptr;
		FileImage* _image = nullptr;

		stacofin::Finder _codeFinder;

		std::set<std::string> _sigPaths;
		std::map<utils::Address, std::string> _imports;

//		std::map<utils::Address, utils::Address> _solvedRefs;
		std::map<utils::Address, std::pair<utils::Address, std::string>> _solvedRefs;
		DetectedFunctionsMultimap _allDetections;
		DetectedFunctionsMultimap _worklistDetections;
		DetectedFunctionsMultimap _rerectedDetections;
		DetectedFunctionsMap _confirmedDetections;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
