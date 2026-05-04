#include "MixedExecution.h"

namespace IronLock::Modules::VM::Lifter {

void MixedExecution::CaptureNativeState(VMExecutionContext& ctx,
                                        const std::array<uint64_t, 16>& regs,
                                        uint64_t sp,
                                        uint64_t ip,
                                        uint64_t flags) {
    ctx.gpr = regs;
    ctx.rsp = sp;
    ctx.rip = ip;
    ctx.rflags = flags;
}

void MixedExecution::RestoreNativeState(const VMExecutionContext& ctx,
                                        std::array<uint64_t, 16>& regs,
                                        uint64_t& sp,
                                        uint64_t& ip,
                                        uint64_t& flags) {
    regs = ctx.gpr;
    sp = ctx.rsp;
    ip = ctx.rip;
    flags = ctx.rflags;
}

} // namespace IronLock::Modules::VM::Lifter
