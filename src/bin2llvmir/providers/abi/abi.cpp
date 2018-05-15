/**
 * @file src/bin2llvmir/providers/abi/abi.cpp
 * @brief ABI information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/abi/arm.h"
#include "retdec/bin2llvmir/providers/abi/mips.h"
#include "retdec/bin2llvmir/providers/abi/powerpc.h"
#include "retdec/bin2llvmir/providers/abi/x86.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// Abi
//==============================================================================
//

const uint32_t Abi::X86_REG_INVALID = 0;

Abi::Abi(llvm::Module* m, Config* c) :
		_module(m),
		_config(c)
{

}

Abi::~Abi()
{

}

bool Abi::isRegister(const llvm::Value* val)
{
	return _regs2id.count(val);
}

bool Abi::isFlagRegister(const llvm::Value* val)
{
	return isRegister(val)
			&& val->getType()->getPointerElementType()->isIntegerTy(1);
}

bool Abi::isStackPointerRegister(const llvm::Value* val)
{
	return getRegister(_regStackPointerId) == val;
}

llvm::GlobalVariable* Abi::getRegister(uint32_t r)
{
	assert(r < _regs.size());
	return _regs[r];
}

uint32_t Abi::getRegisterId(llvm::Value* r)
{
	auto it = _regs2id.find(r);
	return it != _regs2id.end() ? it->second : X86_REG_INVALID;
}

void Abi::addRegister(uint32_t id, llvm::GlobalVariable* reg)
{
	if (id >= _regs.size())
	{
		_regs.resize(id+1, nullptr);
	}
	_regs[id] = reg;
	_regs2id.emplace(reg, id);
}

//
//==============================================================================
// AbiProvider
//==============================================================================
//

std::map<llvm::Module*, std::unique_ptr<Abi>> AbiProvider::_module2abi;

Abi* AbiProvider::addAbi(
		llvm::Module* m,
		Config* c)
{
	if (m == nullptr || c == nullptr)
	{
		return nullptr;
	}

	if (c->getConfig().architecture.isArmOrThumb())
	{
		auto p = _module2abi.emplace(m, std::make_unique<AbiArm>(m, c));
		return p.first->second.get();
	}
	else if (c->getConfig().architecture.isMipsOrPic32())
	{
		auto p = _module2abi.emplace(m, std::make_unique<AbiMips>(m, c));
		return p.first->second.get();
	}
	else if (c->getConfig().architecture.isPpc())
	{
		auto p = _module2abi.emplace(m, std::make_unique<AbiPowerpc>(m, c));
		return p.first->second.get();
	}
	else if (c->getConfig().architecture.isX86())
	{
		auto p = _module2abi.emplace(m, std::make_unique<AbiX86>(m, c));
		return p.first->second.get();
	}
	// ...

	return nullptr;
}

Abi* AbiProvider::getAbi(llvm::Module* m)
{
	auto f = _module2abi.find(m);
	return f != _module2abi.end() ? f->second.get() : nullptr;
}

bool AbiProvider::getAbi(llvm::Module* m, Abi*& abi)
{
	abi = getAbi(m);
	return abi != nullptr;
}

void AbiProvider::clear()
{
	_module2abi.clear();
}

} // namespace bin2llvmir
} // namespace retdec
