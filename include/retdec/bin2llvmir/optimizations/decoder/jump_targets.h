/**
* @file include/retdec/bin2llvmir/optimizations/decoder/jump_targets.h
* @brief Jump targets representation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_JUMP_TARGETS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_JUMP_TARGETS_H

#include <set>

#include "retdec/capstone2llvmir/capstone2llvmir.h"
#include "retdec/capstone2llvmir/x86/x86.h"
#include "retdec/utils/address.h"

namespace retdec {
namespace bin2llvmir {

class JumpTarget
{
	public:
		/**
		 * Jump target type and its priority.
		 * Lower number -> higher priority.
		 */
		enum class eType
		{
			//
			CONTROL_FLOW_BR_FALSE = 0,
			CONTROL_FLOW_BR_TRUE,
			CONTROL_FLOW_SWITCH_CASE,
			CONTROL_FLOW_CALL_TARGET,
			CONTROL_FLOW_RETURN_TARGET,
			//
			ENTRY_POINT,
			LEFTOVER,
			//
			UNKNOWN,
		};

	public:
		JumpTarget();
		JumpTarget(
				retdec::utils::Address a,
				eType t,
				cs_mode m,
				retdec::utils::Address f,
				const std::string& n = "");
		JumpTarget(
				retdec::utils::Address a,
				eType t,
				cs_mode m,
				llvm::Instruction* f,
				const std::string& n = "");

		bool operator<(const JumpTarget& o) const;

		bool hasName() const;
		std::string getName() const;

		bool isKnownMode() const;
		bool isUnknownMode() const;

		llvm::Instruction* getFromInstruction() const;
		retdec::utils::Address getFromAddress() const;

	friend std::ostream& operator<<(std::ostream &out, const JumpTarget& jt);

	public:
		retdec::utils::Address address;
		eType type = eType::UNKNOWN;

	private:
		/// Address from which this jump target was created.
		retdec::utils::Address _fromAddress;
		/// Instruction from which this jump target was created.
		/// This can be used to get from address.
		llvm::Instruction* _fromInst = nullptr;
		cs_mode _mode = CS_MODE_BIG_ENDIAN;
		std::string _name;
};

class JumpTargets
{
	public:
		auto begin();
		auto end();

		bool empty();
		std::size_t size() const;
		void clear();
		const JumpTarget& top();
		void pop();
		bool wasAlreadyPoped(JumpTarget& ct) const;

		void push(
				retdec::utils::Address a,
				JumpTarget::eType t,
				cs_mode m,
				retdec::utils::Address f,
				const std::string& n = "");
		void push(
				retdec::utils::Address a,
				JumpTarget::eType t,
				cs_mode m,
				llvm::Instruction* f,
				const std::string& n = "");

	friend std::ostream& operator<<(std::ostream &out, const JumpTargets& jts);

	private:
		std::set<JumpTarget> _data;
		std::set<retdec::utils::Address> _poped;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
