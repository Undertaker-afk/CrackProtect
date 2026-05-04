#pragma once

#include "IR.h"

namespace IronLock::Modules::VM::Lifter {

class IRNormalizer {
public:
    static void Normalize(LiftedFunction& function);
};

} // namespace IronLock::Modules::VM::Lifter
