#include "InstructionLifter.h"

#include <cstring>
#include <set>
#include <unordered_map>

namespace IronLock::Modules::VM::Lifter {

static uint32_t gSsaCounter = 1;

static uint32_t NextSSA() { return gSsaCounter++; }

std::vector<DecodedInstruction> InstructionLifter::Decode(const uint8_t* code, size_t size, uint64_t baseAddress, Architecture) {
    std::vector<DecodedInstruction> out;
    for (size_t i = 0; i < size; ++i) {
        DecodedInstruction d{};
        d.address = baseAddress + i;
        uint8_t b = code[i];
        if (b == 0x90) d.mnemonic = "nop";
        else if (b == 0xC3) { d.mnemonic = "ret"; d.isControlFlow = true; }
        else if (b == 0xE8 && i + 4 < size) {
            d.mnemonic = "call_rel32"; d.size = 5; d.isControlFlow = true;
            int32_t off = 0; std::memcpy(&off, &code[i + 1], sizeof(off));
            d.relativeTarget = static_cast<int64_t>(d.address + d.size) + off;
            i += 4;
        } else if (b == 0xE9 && i + 4 < size) {
            d.mnemonic = "jmp_rel32"; d.size = 5; d.isControlFlow = true;
            int32_t off = 0; std::memcpy(&off, &code[i + 1], sizeof(off));
            d.relativeTarget = static_cast<int64_t>(d.address + d.size) + off;
            i += 4;
        } else if ((b == 0x74 || b == 0x75) && i + 1 < size) {
            d.mnemonic = (b == 0x74) ? "jz_rel8" : "jnz_rel8";
            d.size = 2; d.isControlFlow = true; d.isConditionalBranch = true;
            int8_t off = static_cast<int8_t>(code[i + 1]);
            d.relativeTarget = static_cast<int64_t>(d.address + d.size) + off;
            i += 1;
        } else if (b == 0x31 && i + 1 < size && code[i + 1] == 0xC0) {
            d.mnemonic = "xor_rax_rax"; d.size = 2; i += 1;
        } else d.mnemonic = "db";
        d.operands.push_back(Operand::Imm(b, 8));
        out.push_back(d);
    }
    return out;
}

LiftedFunction InstructionLifter::LiftFunction(const std::string& name,
                                               const std::string& section,
                                               const std::vector<DecodedInstruction>& decoded,
                                               uint64_t start,
                                               uint64_t end,
                                               Architecture arch,
                                               CallingConvention cc) {
    LiftedFunction fn{};
    fn.name = name;
    fn.section = section;
    fn.start = start;
    fn.end = end;
    fn.arch = arch;
    fn.cc = cc;

    std::set<uint64_t> leaders{start};
    for (const auto& d : decoded) {
        if (d.relativeTarget) leaders.insert(static_cast<uint64_t>(*d.relativeTarget));
        if (d.isConditionalBranch || d.mnemonic.rfind("jmp", 0) == 0) leaders.insert(d.address + d.size);
    }

    std::unordered_map<uint64_t, uint32_t> addrToBlock;
    uint32_t id = 0;
    for (auto leader : leaders) {
        BasicBlock bb{};
        bb.id = id;
        bb.startAddress = leader;
        fn.cfg.blocks.emplace(id, bb);
        addrToBlock[leader] = id++;
    }
    fn.cfg.entryBlock = addrToBlock[start];

    uint32_t current = fn.cfg.entryBlock;
    for (const auto& d : decoded) {
        if (addrToBlock.count(d.address) != 0) current = addrToBlock[d.address];
        auto& bb = fn.cfg.blocks[current];

        IRInstruction ir{};
        ir.id = static_cast<uint32_t>(bb.instructions.size());
        ir.sourceAddress = d.address;
        ir.debugMnemonic = d.mnemonic;

        if (d.mnemonic == "ret") ir.op = IROp::Ret;
        else if (d.mnemonic == "call_rel32") ir.op = IROp::Call;
        else if (d.mnemonic == "jmp_rel32") ir.op = IROp::Jump;
        else if (d.isConditionalBranch) { ir.op = IROp::Branch; ir.readsFlags = {FlagBit::ZF}; }
        else if (d.mnemonic == "xor_rax_rax") {
            ir.op = IROp::Xor;
            ir.inputs = {Operand::Reg(RegisterId::RAX), Operand::Reg(RegisterId::RAX)};
            ir.resultValue = NextSSA();
            ir.writesFlags = {FlagBit::CF, FlagBit::OF, FlagBit::SF, FlagBit::ZF, FlagBit::PF};
        } else {
            ir.op = IROp::Move;
            ir.inputs = d.operands;
            ir.resultValue = NextSSA();
        }
        if (ir.inputs.empty()) ir.inputs = d.operands;
        bb.instructions.push_back(ir);

        if (d.relativeTarget && addrToBlock.count(static_cast<uint64_t>(*d.relativeTarget))) {
            bb.successors.push_back(addrToBlock[static_cast<uint64_t>(*d.relativeTarget)]);
        }
        if (d.isConditionalBranch && addrToBlock.count(d.address + d.size)) {
            bb.successors.push_back(addrToBlock[d.address + d.size]);
        }
    }

    for (auto& [bid, b] : fn.cfg.blocks) {
        for (auto succ : b.successors) fn.cfg.blocks[succ].predecessors.push_back(bid);
    }
    return fn;
}

} // namespace
