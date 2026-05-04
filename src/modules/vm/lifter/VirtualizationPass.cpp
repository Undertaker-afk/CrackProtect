#include "VirtualizationPass.h"

namespace IronLock::Modules::VM::Lifter {

bool VirtualizationPass::ShouldVirtualize(const LiftedFunction& function, const FunctionSelector& selector) {
    if (selector.symbol && function.name != *selector.symbol) return false;
    if (selector.section && function.section != *selector.section) return false;
    if (selector.start && function.start < *selector.start) return false;
    if (selector.end && function.end > *selector.end) return false;
    return true;
}

VMTrampoline VirtualizationPass::BuildDispatchTrampoline(const LiftedFunction& function, uint64_t vmRuntimeEntry) {
    VMTrampoline out{};
    out.nativeEntry = function.start;
    out.vmEntry = vmRuntimeEntry;

    // x64 mov rax, imm64; jmp rax
    out.patchBytes = {0x48, 0xB8,
                      static_cast<uint8_t>(vmRuntimeEntry & 0xFF), static_cast<uint8_t>((vmRuntimeEntry >> 8) & 0xFF),
                      static_cast<uint8_t>((vmRuntimeEntry >> 16) & 0xFF), static_cast<uint8_t>((vmRuntimeEntry >> 24) & 0xFF),
                      static_cast<uint8_t>((vmRuntimeEntry >> 32) & 0xFF), static_cast<uint8_t>((vmRuntimeEntry >> 40) & 0xFF),
                      static_cast<uint8_t>((vmRuntimeEntry >> 48) & 0xFF), static_cast<uint8_t>((vmRuntimeEntry >> 56) & 0xFF),
                      0xFF, 0xE0};
    return out;
}

} // namespace IronLock::Modules::VM::Lifter
