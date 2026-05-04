#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace IronLock::Modules::VM::Lifter {

enum class Architecture : uint8_t { X86, X64 };
enum class CallingConvention : uint8_t { Cdecl, Stdcall, Fastcall, Win64, SysV64, Unknown };
enum class RegisterId : uint16_t {
    INVALID = 0,
    RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP,
    R8, R9, R10, R11, R12, R13, R14, R15,
    EFLAGS
};

enum class IROp : uint16_t {
    Nop,
    Constant,
    Phi,
    Move,
    Add, Sub, Mul, Div, Mod,
    And, Or, Xor, Not,
    Shl, Shr, Sar, Rol, Ror,
    Load, Store,
    Cmp, Test,
    SetFlag,
    Jump,
    Branch,
    Call,
    Ret
};

enum class FlagBit : uint8_t { CF, PF, AF, ZF, SF, OF };

struct Operand {
    enum class Kind : uint8_t { Invalid, SSAValue, Register, Immediate, Memory } kind = Kind::Invalid;
    uint64_t value = 0;
    uint8_t widthBits = 64;
    int32_t displacement = 0;

    static Operand SSA(uint32_t v, uint8_t width = 64) { return {Kind::SSAValue, v, width, 0}; }
    static Operand Reg(RegisterId r, uint8_t width = 64) { return {Kind::Register, static_cast<uint64_t>(r), width, 0}; }
    static Operand Imm(uint64_t v, uint8_t width = 64) { return {Kind::Immediate, v, width, 0}; }
};

struct IRInstruction {
    uint32_t id = 0;
    IROp op = IROp::Nop;
    std::optional<uint32_t> resultValue;
    std::vector<Operand> inputs;
    std::vector<FlagBit> writesFlags;
    std::vector<FlagBit> readsFlags;
    uint64_t sourceAddress = 0;
    std::string debugMnemonic;
};

struct BasicBlock {
    uint32_t id = 0;
    uint64_t startAddress = 0;
    std::vector<IRInstruction> instructions;
    std::vector<uint32_t> successors;
    std::vector<uint32_t> predecessors;
};

struct ControlFlowGraph {
    uint32_t entryBlock = 0;
    std::unordered_map<uint32_t, BasicBlock> blocks;
};

struct LiftedFunction {
    std::string name;
    std::string section;
    uint64_t start = 0;
    uint64_t end = 0;
    Architecture arch = Architecture::X64;
    CallingConvention cc = CallingConvention::Unknown;
    ControlFlowGraph cfg;
};

} // namespace IronLock::Modules::VM::Lifter
