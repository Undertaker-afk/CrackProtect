#include "ControlFlow.h"
#include <windows.h>

extern "C" void IL_OpaquePredicate();
extern "C" void IL_JunkCode();

namespace IronLock::Modules::Obfuscation {

void OpaquePredicate() {
#ifdef _WIN64
    IL_OpaquePredicate();
#else
    __asm {
        xor eax, eax
        jz label1
        __emit 0xEA
    label1:
    }
#endif
}

void JunkCode() {
#ifdef _WIN64
    IL_JunkCode();
#else
    __asm {
        push eax
        xor eax, eax
        test eax, eax
        jnz label_junk
        pop eax
        jmp label_end
    label_junk:
        __emit 0xFF
        __emit 0x12
    label_end:
    }
#endif
}

} // namespace IronLock::Modules::Obfuscation
