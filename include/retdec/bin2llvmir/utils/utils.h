/**
 * @file include/retdec/bin2llvmir/utils/utils.h
 * @brief LLVM Utility functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_UTILS_H
#define RETDEC_BIN2LLVMIR_UTILS_UTILS_H

#include <llvm/IR/Value.h>

namespace retdec {
namespace bin2llvmir {

llvm::Value* skipCasts(llvm::Value* val);

} // namespace bin2llvmir
} // namespace retdec

#endif
