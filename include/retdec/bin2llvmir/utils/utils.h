/**
 * @file include/retdec/bin2llvmir/utils/utils.h
 * @brief LLVM Utility functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_UTILS_H
#define RETDEC_BIN2LLVMIR_UTILS_UTILS_H

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/filesystem_path.h"

namespace retdec {
namespace bin2llvmir {

/**
 * Print any LLVM object which implements @c print(llvm::raw_string_ostream&)
 * method into std::string.
 * @param t LLVM object to print.
 * @return String with printed object.
 */
template<typename T>
std::string llvmObjToString(const T* t)
{
	std::string str;
	llvm::raw_string_ostream ss(str);
	if (t)
		t->print(ss);
	else
		ss << "nullptr";
	return ss.str();
}
std::string llvmObjToString(const llvm::Module* t);
std::string llvmObjToString(const llvm::Module& t);

void dumpModuleToFile(
		const llvm::Module* m,
		utils::FilesystemPath dirName,
		const std::string fileName = "");
void dumpControFlowToJson(
		llvm::Module* m,
		utils::FilesystemPath dirName,
		const std::string& fileName = "control-flow.json");

llvm::Value* skipCasts(llvm::Value* val);

} // namespace bin2llvmir
} // namespace retdec

#endif
