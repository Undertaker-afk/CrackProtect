#pragma once

#include <cstdint>

namespace IronLock::Modules::VM::Lifter {

enum class VMOpcode : uint16_t {
    Nop,
    Mov,
    Add, Sub, Mul, Div, Mod,
    And, Or, Xor, Not,
    Shl, Shr, Sar, Rol, Ror,
    Load8, Load16, Load32, Load64,
    Store8, Store16, Store32, Store64,
    Lea,
    Cmp,
    SetFlags,
    Jmp,
    Jcc,
    Call,
    Ret
};

} // namespace IronLock::Modules::VM::Lifter
