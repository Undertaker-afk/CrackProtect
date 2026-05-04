#pragma once

#include "IR.h"

#include <optional>
#include <string>
#include <vector>

namespace IronLock::Modules::VM::Lifter {

struct FunctionSelector {
    std::optional<std::string> symbol;
    std::optional<std::string> section;
    std::optional<uint64_t> start;
    std::optional<uint64_t> end;
};

struct VMTrampoline {
    uint64_t nativeEntry = 0;
    uint64_t vmEntry = 0;
    std::vector<uint8_t> patchBytes;
};

class VirtualizationPass {
public:
    static bool ShouldVirtualize(const LiftedFunction& function, const FunctionSelector& selector);
    static VMTrampoline BuildDispatchTrampoline(const LiftedFunction& function, uint64_t vmRuntimeEntry);
};

} // namespace IronLock::Modules::VM::Lifter
