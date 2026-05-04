#pragma once

#include "IR.h"

#include <cstdint>
#include <string>
#include <vector>

namespace IronLock::Modules::VM::Lifter {

struct DecodedInstruction {
    uint64_t address = 0;
    std::string mnemonic;
    std::vector<Operand> operands;
    uint32_t size = 1;
    bool isControlFlow = false;
    bool isConditionalBranch = false;
    std::optional<int64_t> relativeTarget;
};

class InstructionLifter {
public:
    static std::vector<DecodedInstruction> Decode(const uint8_t* code, size_t size, uint64_t baseAddress, Architecture arch);
    static LiftedFunction LiftFunction(const std::string& name,
                                       const std::string& section,
                                       const std::vector<DecodedInstruction>& decoded,
                                       uint64_t start,
                                       uint64_t end,
                                       Architecture arch,
                                       CallingConvention cc);
};

} // namespace IronLock::Modules::VM::Lifter
