/**
* @file tests/bin2llvmir/optimizations/inst_opt/inst_opt_tests.cpp
* @brief Tests for the @c inst_opt::optimize().
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "bin2llvmir/utils/llvmir_tests.h"
#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
 * @brief Tests for the @c inst_opt::optimize().
 */
class OptimizeTests: public LlvmIrTests
{

};

//
// no optimization
//

TEST_F(OptimizeTests, noOptimizationReturnsFalse)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)");
	auto* i = getInstructionByName("a");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_FALSE(ret);
}

//
// add zero
//

TEST_F(OptimizeTests, addValZero)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 %a, 0
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, addZeroVal)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 0, %a
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, addValVal)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 %a, 10
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = add i32 %a, 10
			ret i32 %b
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_FALSE(ret);
}

//
// sub zero
//

TEST_F(OptimizeTests, subValZero)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = sub i32 %a, 0
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, subValVal)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = sub i32 %a, 10
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = sub i32 %a, 10
			ret i32 %b
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_FALSE(ret);
}

//
// trunc zext
//

TEST_F(OptimizeTests, truncZext8)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = trunc i32 %a to i8
			%c = zext i8 %b to i32
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%c = and i32 %a, 255
			ret i32 %c
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, truncZext16)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = trunc i32 %a to i16
			%c = zext i16 %b to i32
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%c = and i32 %a, 65535
			ret i32 %c
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// xor X, X
//

TEST_F(OptimizeTests, xorXX)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = xor i32 10, 10
			ret i32 %a
		}
	)");
	auto* i = getInstructionByName("a");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		define i32 @fnc() {
			ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// xor load X, load X
//

TEST_F(OptimizeTests, xorLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = xor i32 %a, %a
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, xorLoadXLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = load i32, i32* @reg
			%c = xor i32 %a, %b
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			ret i32 0
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// or X, X
//

TEST_F(OptimizeTests, orXX)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = or i32 10, 10
			ret i32 %a
		}
	)");
	auto* i = getInstructionByName("a");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		define i32 @fnc() {
			ret i32 10
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// and X, X
//

TEST_F(OptimizeTests, andXX)
{
	parseInput(R"(
		define i32 @fnc() {
			%a = and i32 10, 10
			ret i32 %a
		}
	)");
	auto* i = getInstructionByName("a");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		define i32 @fnc() {
			ret i32 10
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// or load X, load X
//

TEST_F(OptimizeTests, orLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = or i32 %a, %a
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, orLoadXLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = load i32, i32* @reg
			%c = or i32 %a, %b
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

//
// and load X, load X
//

TEST_F(OptimizeTests, andLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = and i32 %a, %a
			ret i32 %b
		}
	)");
	auto* i = getInstructionByName("b");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

TEST_F(OptimizeTests, andLoadXLoadX)
{
	parseInput(R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			%b = load i32, i32* @reg
			%c = and i32 %a, %b
			ret i32 %c
		}
	)");
	auto* i = getInstructionByName("c");

	bool ret = inst_opt::optimize(i);

	std::string exp = R"(
		@reg = global i32 0
		define i32 @fnc() {
			%a = load i32, i32* @reg
			ret i32 %a
		}
	)";
	checkModuleAgainstExpectedIr(exp);
	EXPECT_TRUE(ret);
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
