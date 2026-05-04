#include "IRNormalizer.h"

namespace IronLock::Modules::VM::Lifter {

static IROp Canonicalize(IROp op) {
    if (op == IROp::Test) return IROp::And;
    return op;
}

void IRNormalizer::Normalize(LiftedFunction& function) {
    for (auto& [_, block] : function.cfg.blocks) {
        std::vector<IRInstruction> normalized;
        for (const auto& in : block.instructions) {
            IRInstruction inst = in;
            inst.op = Canonicalize(inst.op);

            if (inst.op == IROp::Rol || inst.op == IROp::Ror) {
                IRInstruction shift = inst;
                shift.op = (inst.op == IROp::Rol) ? IROp::Shl : IROp::Shr;
                normalized.push_back(shift);
                IRInstruction wrap = inst;
                wrap.op = (inst.op == IROp::Rol) ? IROp::Shr : IROp::Shl;
                normalized.push_back(wrap);
                IRInstruction combine = inst;
                combine.op = IROp::Or;
                normalized.push_back(combine);
                continue;
            }

            if (inst.op == IROp::Store && inst.inputs.size() >= 3) {
                IRInstruction addr{};
                addr = inst;
                addr.op = IROp::Add;
                addr.inputs = {inst.inputs[0], inst.inputs[1]};
                normalized.push_back(addr);

                inst.inputs = {Operand::SSA(addr.resultValue.value_or(0)), inst.inputs.back()};
            }

            if (inst.op == IROp::Cmp) {
                inst.writesFlags = {FlagBit::CF, FlagBit::OF, FlagBit::SF, FlagBit::ZF, FlagBit::AF, FlagBit::PF};
            }
            normalized.push_back(inst);
        }
        block.instructions = std::move(normalized);
    }
}

} // namespace IronLock::Modules::VM::Lifter
