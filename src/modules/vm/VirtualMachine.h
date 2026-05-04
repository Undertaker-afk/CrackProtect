#pragma once
#include <vector>
#include <cstdint>

namespace IronLock::Modules::VM {

enum class OpCode : uint8_t {
    OP_PUSH = 0x10,
    OP_POP  = 0x11,
    OP_ADD  = 0x20,
    OP_SUB  = 0x21,
    OP_XOR  = 0x22,
    OP_CMP  = 0x30,
    OP_JMP  = 0x40,
    OP_JZ   = 0x41,
    OP_RET  = 0xFF
};

class VirtualMachine {
public:
    static uint64_t Execute(const std::vector<uint8_t>& bytecode);

private:
    struct VMContext {
        uint64_t stack[256];
        uint8_t sp = 0;
        uint32_t pc = 0;
        bool zf = false;
    };
};

} // namespace IronLock::Modules::VM

// Header-based "compiler" macros
#define VM_START std::vector<uint8_t> __bc = {
#define VM_PUSH(val) (uint8_t)IronLock::Modules::VM::OpCode::OP_PUSH, (uint8_t)((val) & 0xFF), (uint8_t)(((val) >> 8) & 0xFF),
#define VM_ADD (uint8_t)IronLock::Modules::VM::OpCode::OP_ADD,
#define VM_RET (uint8_t)IronLock::Modules::VM::OpCode::OP_RET
#define VM_END }; return IronLock::Modules::VM::VirtualMachine::Execute(__bc);
