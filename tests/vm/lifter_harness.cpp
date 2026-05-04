#include "modules/vm/lifter/IRNormalizer.h"
#include "modules/vm/lifter/InstructionLifter.h"
#include "modules/vm/lifter/MixedExecution.h"
#include "modules/vm/lifter/VirtualizationPass.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

using namespace IronLock::Modules::VM::Lifter;

int main() {
    const std::vector<uint8_t> fnBytes = {
        0x31, 0xC0,       // xor rax,rax
        0x74, 0x02,       // jz +2
        0x90,             // nop
        0xC3              // ret
    };

    auto decoded = InstructionLifter::Decode(fnBytes.data(), fnBytes.size(), 0x1000, Architecture::X64);
    auto lifted = InstructionLifter::LiftFunction("golden_basic_block", ".text", decoded, 0x1000, 0x1006, Architecture::X64, CallingConvention::Win64);
    IRNormalizer::Normalize(lifted);

    assert(lifted.cfg.blocks.size() >= 2);
    bool foundBranch = false;
    for (const auto& [_, block] : lifted.cfg.blocks) {
        for (const auto& inst : block.instructions) {
            if (inst.op == IROp::Branch) foundBranch = true;
        }
    }
    assert(foundBranch);

    FunctionSelector selector{};
    selector.symbol = "golden_basic_block";
    selector.section = ".text";
    assert(VirtualizationPass::ShouldVirtualize(lifted, selector));
    auto tramp = VirtualizationPass::BuildDispatchTrampoline(lifted, 0xCAFEBABEDEADBEEFULL);
    assert(tramp.patchBytes.size() == 12);

    std::array<uint64_t, 16> regs{};
    regs[0] = 42;
    VMExecutionContext ctx{};
    MixedExecution::CaptureNativeState(ctx, regs, 0x7000, 0x1000, 0x246);

    std::array<uint64_t, 16> restored{};
    uint64_t sp = 0, ip = 0, flags = 0;
    MixedExecution::RestoreNativeState(ctx, restored, sp, ip, flags);
    assert(restored[0] == 42 && sp == 0x7000 && ip == 0x1000 && flags == 0x246);

    return 0;
}
