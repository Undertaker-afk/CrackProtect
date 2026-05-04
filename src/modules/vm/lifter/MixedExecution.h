#pragma once

#include <array>
#include <cstdint>

namespace IronLock::Modules::VM::Lifter {

struct VMExecutionContext {
    std::array<uint64_t, 16> gpr{};
    std::array<uint64_t, 64> shadowStack{};
    uint64_t rip = 0;
    uint64_t rsp = 0;
    uint64_t rflags = 0;
};

class MixedExecution {
public:
    static void CaptureNativeState(VMExecutionContext& ctx, const std::array<uint64_t, 16>& regs, uint64_t sp, uint64_t ip, uint64_t flags);
    static void RestoreNativeState(const VMExecutionContext& ctx, std::array<uint64_t, 16>& regs, uint64_t& sp, uint64_t& ip, uint64_t& flags);
};

} // namespace IronLock::Modules::VM::Lifter
