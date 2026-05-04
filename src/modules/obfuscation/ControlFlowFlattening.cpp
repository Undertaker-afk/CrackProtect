#include "ControlFlowFlattening.h"
#include <algorithm>
#include <cstring>

namespace IronLock::Modules::Obfuscation {

// Local SSA counter for obfuscation module
static uint32_t sSsaCounter = 10000;
static uint32_t NextSSA() { return sSsaCounter++; }

uint32_t ControlFlowFlattener::GenerateStateValue(std::mt19937& rng, uint32_t bits) {
    std::uniform_int_distribution<uint32_t> dist(1, (1u << bits) - 1);
    return dist(rng);
}

Lifter::IRInstruction ControlFlowFlattener::GenerateStateCheck(uint32_t expectedState, Lifter::RegisterId stateReg) {
    Lifter::IRInstruction ir;
    ir.op = Lifter::IROp::Cmp;
    ir.inputs = {Lifter::Operand::Reg(stateReg), Lifter::Operand::Imm(expectedState, 32)};
    ir.writesFlags = {Lifter::FlagBit::ZF};
    return ir;
}

Lifter::IRInstruction ControlFlowFlattener::GenerateStateUpdate(uint32_t newState, Lifter::RegisterId stateReg) {
    Lifter::IRInstruction ir;
    ir.op = Lifter::IROp::Move;
    ir.inputs = {Lifter::Operand::Imm(newState, 32)};
    ir.resultValue = NextSSA();
    return ir;
}

std::vector<Lifter::IRInstruction> ControlFlowFlattener::GenerateOpaquePredicateTrue(std::mt19937& rng) {
    std::vector<Lifter::IRInstruction> ops;
    // (x * (x + 1)) is always even, so ((x * (x + 1)) % 2) == 0 is always true
    std::uniform_int_distribution<uint32_t> dist(1, 0xFFFFFFFF);
    uint32_t x = dist(rng);
    
    Lifter::IRInstruction loadX{};
    loadX.op = Lifter::IROp::Constant;
    loadX.resultValue = NextSSA();
    loadX.inputs = {Lifter::Operand::Imm(x, 32)};
    ops.push_back(loadX);
    
    Lifter::IRInstruction addOne{};
    addOne.op = Lifter::IROp::Add;
    addOne.resultValue = NextSSA();
    addOne.inputs = {Lifter::Operand::SSA(loadX.resultValue.value()), Lifter::Operand::Imm(1, 32)};
    ops.push_back(addOne);
    
    Lifter::IRInstruction mul{};
    mul.op = Lifter::IROp::Mul;
    mul.resultValue = NextSSA();
    mul.inputs = {Lifter::Operand::SSA(loadX.resultValue.value()), Lifter::Operand::SSA(addOne.resultValue.value())};
    ops.push_back(mul);
    
    Lifter::IRInstruction mod2{};
    mod2.op = Lifter::IROp::Mod;
    mod2.resultValue = NextSSA();
    mod2.inputs = {Lifter::Operand::SSA(mul.resultValue.value()), Lifter::Operand::Imm(2, 32)};
    ops.push_back(mod2);
    
    Lifter::IRInstruction cmp{};
    cmp.op = Lifter::IROp::Cmp;
    cmp.inputs = {Lifter::Operand::SSA(mod2.resultValue.value()), Lifter::Operand::Imm(0, 32)};
    cmp.writesFlags = {Lifter::FlagBit::ZF};
    ops.push_back(cmp);
    
    return ops;
}

std::vector<Lifter::IRInstruction> ControlFlowFlattener::GenerateOpaquePredicateFalse(std::mt19937& rng) {
    std::vector<Lifter::IRInstruction> ops;
    // (x^2) >= 0 is always true for integers, so (x^2 < 0) is always false
    std::uniform_int_distribution<uint32_t> dist(1, 0xFFFF);
    uint32_t x = dist(rng);
    
    Lifter::IRInstruction loadX{};
    loadX.op = Lifter::IROp::Constant;
    loadX.resultValue = NextSSA();
    loadX.inputs = {Lifter::Operand::Imm(x, 32)};
    ops.push_back(loadX);
    
    Lifter::IRInstruction square{};
    square.op = Lifter::IROp::Mul;
    square.resultValue = NextSSA();
    square.inputs = {Lifter::Operand::SSA(loadX.resultValue.value()), Lifter::Operand::SSA(loadX.resultValue.value())};
    ops.push_back(square);
    
    Lifter::IRInstruction cmp{};
    cmp.op = Lifter::IROp::Cmp;
    cmp.inputs = {Lifter::Operand::SSA(square.resultValue.value()), Lifter::Operand::Imm(0, 32)};
    cmp.writesFlags = {Lifter::FlagBit::SF};
    ops.push_back(cmp);
    
    return ops;
}

std::vector<Lifter::IRInstruction> ControlFlowFlattener::GenerateJunkCode(std::mt19937& rng) {
    std::vector<Lifter::IRInstruction> junk;
    std::uniform_int_distribution<size_t> countDist(3, 10);
    size_t count = countDist(rng);
    
    for (size_t i = 0; i < count; ++i) {
        std::uniform_int_distribution<int> opDist(0, 4);
        int op = opDist(rng);
        
        Lifter::IRInstruction ir{};
        ir.sourceAddress = 0xDEADBEEF;
        
        switch (op) {
            case 0: // Dead store
                ir.op = Lifter::IROp::Move;
                ir.resultValue = NextSSA();
                ir.inputs = {Lifter::Operand::Imm(rng(), 32)};
                break;
            case 1: // Useless arithmetic
                ir.op = Lifter::IROp::Add;
                ir.resultValue = NextSSA();
                ir.inputs = {Lifter::Operand::Imm(rng(), 32), Lifter::Operand::Imm(0, 32)};
                break;
            case 2: // XOR self (zeroes result, dead)
                ir.op = Lifter::IROp::Xor;
                ir.resultValue = NextSSA();
                ir.inputs = {Lifter::Operand::Imm(rng(), 32), Lifter::Operand::Imm(rng(), 32)};
                break;
            case 3: // Flag trash
                ir.op = Lifter::IROp::Test;
                ir.inputs = {Lifter::Operand::Imm(rng(), 32), Lifter::Operand::Imm(1, 32)};
                ir.writesFlags = {Lifter::FlagBit::ZF, Lifter::FlagBit::SF, Lifter::FlagBit::PF};
                break;
            default: // NOP equivalent
                ir.op = Lifter::IROp::Nop;
                break;
        }
        junk.push_back(ir);
    }
    return junk;
}

void ControlFlowFlattener::InsertBogusBlocks(FlattenedFunction& flattened, const FlatteningConfig& config, std::mt19937& rng) {
    uint32_t nextId = 0;
    for (const auto& [id, block] : flattened.blocks) {
        if (id > nextId) nextId = id;
    }
    ++nextId;
    
    for (uint32_t i = 0; i < config.bogusBlocks; ++i) {
        FlattenedBlock bogus;
        bogus.originalId = 0xFFFFFFFF;
        bogus.stateValue = GenerateStateValue(rng, config.stateBits);
        bogus.isBogus = true;
        
        // Add junk instructions
        auto junk = GenerateJunkCode(rng);
        bogus.instructions.insert(bogus.instructions.end(), junk.begin(), junk.end());
        
        // Point to random successor
        std::uniform_int_distribution<uint32_t> succDist(0, flattened.blocks.size() - 1);
        uint32_t targetIdx = succDist(rng);
        uint32_t targetId = 0;
        uint32_t idx = 0;
        for (const auto& [id, blk] : flattened.blocks) {
            if (idx++ == targetIdx) { targetId = id; break; }
        }
        bogus.successors.push_back(targetId);
        
        flattened.blocks[nextId++] = bogus;
    }
}

void ControlFlowFlattener::InsertOpaquePredicates(FlattenedFunction& flattened, const FlatteningConfig& config, std::mt19937& rng) {
    for (auto& [id, block] : flattened.blocks) {
        if (block.isBogus || block.isOpaque) continue;
        
        std::uniform_int_distribution<int> predDist(0, 10);
        if (predDist(rng) < config.opaquePredicates) {
            block.isOpaque = true;
            
            // Insert opaque predicate at start
            auto preds = (rng() & 1) ? GenerateOpaquePredicateTrue(rng) : GenerateOpaquePredicateFalse(rng);
            block.instructions.insert(block.instructions.begin(), preds.begin(), preds.end());
        }
    }
}

void ControlFlowFlattener::BuildDispatchBlock(FlattenedFunction& flattened) {
    FlattenedBlock dispatch;
    dispatch.originalId = 0xFFFFFFFE;
    dispatch.stateValue = 0;
    dispatch.isBogus = false;
    
    // Dispatch block compares state register against all possible states
    // This is simplified - real impl would use jump table or binary search
    Lifter::IRInstruction stateCheck{};
    stateCheck.op = Lifter::IROp::Cmp;
    stateCheck.inputs = {Lifter::Operand::Reg(flattened.stateRegister), Lifter::Operand::Imm(0, 32)};
    stateCheck.writesFlags = {Lifter::FlagBit::ZF};
    dispatch.instructions.push_back(stateCheck);
    
    // Branch based on state
    Lifter::IRInstruction branch{};
    branch.op = Lifter::IROp::Branch;
    branch.readsFlags = {Lifter::FlagBit::ZF};
    dispatch.instructions.push_back(branch);
    
    flattened.dispatchBlockId = 0xFFFFFFFE;
    flattened.blocks[flattened.dispatchBlockId] = dispatch;
}

void ControlFlowFlattener::MutateStateTransitions(FlattenedFunction& flattened, std::mt19937& rng) {
    for (auto& [id, block] : flattened.blocks) {
        if (block.isBogus || id == flattened.dispatchBlockId) continue;
        
        // Encode state transitions with simple mutation
        for (auto& succ : block.successors) {
            if (flattened.blocks.count(succ)) {
                flattened.blocks[succ].stateValue ^= (rng() & 0xFFFF);
            }
        }
    }
}

FlattenedFunction ControlFlowFlattener::Flatten(Lifter::LiftedFunction& fn, const FlatteningConfig& config) {
    FlattenedFunction flattened;
    flattened.stateRegister = Lifter::RegisterId::RAX;
    
    std::random_device rd;
    std::mt19937 rng(rd());
    
    // Assign state values to each original block
    uint32_t stateCounter = 1;
    for (auto& [id, bb] : fn.cfg.blocks) {
        FlattenedBlock fb;
        fb.originalId = id;
        fb.stateValue = stateCounter++;
        
        // Copy instructions
        for (const auto& ir : bb.instructions) {
            fb.instructions.push_back(ir);
        }
        
        // Copy successors
        fb.successors = bb.successors;
        
        flattened.blocks[id] = fb;
    }
    
    flattened.initialState = flattened.blocks[fn.cfg.entryBlock].stateValue;
    flattened.exitState = 0;
    
    // Insert bogus blocks
    InsertBogusBlocks(flattened, config, rng);
    
    // Insert opaque predicates
    InsertOpaquePredicates(flattened, config, rng);
    
    // Build dispatch block
    BuildDispatchBlock(flattened);
    
    // Mutate state transitions
    MutateStateTransitions(flattened, rng);
    
    return flattened;
}

std::vector<uint8_t> ControlFlowFlattener::GenerateDispatchStub(const FlattenedFunction& flattened) {
    std::vector<uint8_t> stub;
    
    // Simplified dispatch stub - in production this would be much more complex
    // Entry: EAX contains state value
    
    // Push state register
    stub.push_back(0x50); // push rax
    
    // Compare state and jump to handler
    // This is a placeholder - real impl generates full dispatch logic
    
    // Pop state register  
    stub.push_back(0x58); // pop rax
    
    // Return to caller
    stub.push_back(0xC3); // ret
    
    return stub;
}

// Opaque Predicate Generator Implementation
std::vector<Lifter::IRInstruction> OpaquePredicateGenerator::Generate(PredicateType type, std::mt19937& rng) {
    switch (type) {
        case PredicateType::AlwaysTrue:
        case PredicateType::InvariantTrue:
            return ControlFlowFlattener::GenerateOpaquePredicateTrue(rng);
        case PredicateType::AlwaysFalse:
        case PredicateType::InvariantFalse:
            return ControlFlowFlattener::GenerateOpaquePredicateFalse(rng);
        case PredicateType::Mathematical:
            return (rng() & 1) ? GenerateMathematicalTrue(rng) : GenerateMathematicalFalse(rng);
        case PredicateType::Bitwise:
            return (rng() & 1) ? GenerateBitwiseTrue(rng) : GenerateBitwiseFalse(rng);
        default:
            return {};
    }
}

std::vector<uint8_t> OpaquePredicateGenerator::GenerateMachineCode(PredicateType type, std::mt19937& rng) {
    std::vector<uint8_t> code;
    
    if (type == PredicateType::AlwaysTrue || type == PredicateType::InvariantTrue) {
        // XOR EAX, EAX; INC EAX; TEST EAX, EAX (ZF=0, meaning not zero = true)
        code = {0x31, 0xC0, 0x40, 0x85, 0xC0};
    } else {
        // XOR EAX, EAX; TEST EAX, EAX (ZF=1, meaning zero = false)
        code = {0x31, 0xC0, 0x85, 0xC0};
    }
    
    return code;
}

std::vector<Lifter::IRInstruction> OpaquePredicateGenerator::GenerateMathematicalTrue(std::mt19937& rng) {
    return ControlFlowFlattener::GenerateOpaquePredicateTrue(rng);
}

std::vector<Lifter::IRInstruction> OpaquePredicateGenerator::GenerateMathematicalFalse(std::mt19937& rng) {
    return ControlFlowFlattener::GenerateOpaquePredicateFalse(rng);
}

std::vector<Lifter::IRInstruction> OpaquePredicateGenerator::GenerateBitwiseTrue(std::mt19937& rng) {
    std::vector<Lifter::IRInstruction> ops;
    // (x | ~x) == 0xFFFFFFFF is always true
    uint32_t x = rng();
    
    Lifter::IRInstruction loadX{};
    loadX.op = Lifter::IROp::Constant;
    loadX.resultValue = NextSSA();
    loadX.inputs = {Lifter::Operand::Imm(x, 32)};
    ops.push_back(loadX);
    
    Lifter::IRInstruction notX{};
    notX.op = Lifter::IROp::Not;
    notX.resultValue = NextSSA();
    notX.inputs = {Lifter::Operand::SSA(loadX.resultValue.value())};
    ops.push_back(notX);
    
    Lifter::IRInstruction orOp{};
    orOp.op = Lifter::IROp::Or;
    orOp.resultValue = NextSSA();
    orOp.inputs = {Lifter::Operand::SSA(loadX.resultValue.value()), Lifter::Operand::SSA(notX.resultValue.value())};
    ops.push_back(orOp);
    
    Lifter::IRInstruction cmp{};
    cmp.op = Lifter::IROp::Cmp;
    cmp.inputs = {Lifter::Operand::SSA(orOp.resultValue.value()), Lifter::Operand::Imm(0xFFFFFFFF, 32)};
    cmp.writesFlags = {Lifter::FlagBit::ZF};
    ops.push_back(cmp);
    
    return ops;
}

std::vector<Lifter::IRInstruction> OpaquePredicateGenerator::GenerateBitwiseFalse(std::mt19937& rng) {
    std::vector<Lifter::IRInstruction> ops;
    // (x & ~x) == 0 is always true, so != 0 is always false
    uint32_t x = rng();
    
    Lifter::IRInstruction loadX{};
    loadX.op = Lifter::IROp::Constant;
    loadX.resultValue = NextSSA();
    loadX.inputs = {Lifter::Operand::Imm(x, 32)};
    ops.push_back(loadX);
    
    Lifter::IRInstruction notX{};
    notX.op = Lifter::IROp::Not;
    notX.resultValue = NextSSA();
    notX.inputs = {Lifter::Operand::SSA(loadX.resultValue.value())};
    ops.push_back(notX);
    
    Lifter::IRInstruction andOp{};
    andOp.op = Lifter::IROp::And;
    andOp.resultValue = NextSSA();
    andOp.inputs = {Lifter::Operand::SSA(loadX.resultValue.value()), Lifter::Operand::SSA(notX.resultValue.value())};
    ops.push_back(andOp);
    
    Lifter::IRInstruction cmp{};
    cmp.op = Lifter::IROp::Cmp;
    cmp.inputs = {Lifter::Operand::SSA(andOp.resultValue.value()), Lifter::Operand::Imm(0, 32)};
    cmp.writesFlags = {Lifter::FlagBit::ZF};
    ops.push_back(cmp);
    
    return ops;
}

// Junk Code Generator Implementation
std::vector<Lifter::IRInstruction> JunkCodeGenerator::GenerateJunk(size_t count, std::mt19937& rng) {
    std::vector<Lifter::IRInstruction> junk;
    for (size_t i = 0; i < count; ++i) {
        std::uniform_int_distribution<int> genDist(0, 3);
        switch (genDist(rng)) {
            case 0: junk.push_back(GenerateDeadStore(rng)); break;
            case 1: junk.push_back(GenerateNopSequence(rng)); break;
            case 2: junk.push_back(GenerateFlagTrash(rng)); break;
            case 3: junk.push_back(GenerateStackPivot(rng)); break;
        }
    }
    return junk;
}

std::vector<uint8_t> JunkCodeGenerator::GenerateJunkBytes(size_t count, std::mt19937& rng) {
    std::vector<uint8_t> junk;
    std::uniform_int_distribution<size_t> byteCount(1, 15);
    
    while (junk.size() < count) {
        size_t n = byteCount(rng);
        for (size_t i = 0; i < n && junk.size() < count; ++i) {
            junk.push_back(static_cast<uint8_t>(rng() & 0xFF));
        }
    }
    return junk;
}

Lifter::IRInstruction JunkCodeGenerator::GenerateDeadStore(std::mt19937& rng) {
    Lifter::IRInstruction ir;
    ir.op = Lifter::IROp::Move;
    ir.resultValue = NextSSA();
    ir.inputs = {Lifter::Operand::Imm(rng(), 32)};
    return ir;
}

Lifter::IRInstruction JunkCodeGenerator::GenerateNopSequence(std::mt19937&) {
    Lifter::IRInstruction ir;
    ir.op = Lifter::IROp::Nop;
    return ir;
}

Lifter::IRInstruction JunkCodeGenerator::GenerateFlagTrash(std::mt19937& rng) {
    Lifter::IRInstruction ir;
    ir.op = Lifter::IROp::Test;
    ir.inputs = {Lifter::Operand::Imm(rng(), 32), Lifter::Operand::Imm(1, 32)};
    ir.writesFlags = {Lifter::FlagBit::ZF, Lifter::FlagBit::SF, Lifter::FlagBit::PF, Lifter::FlagBit::CF, Lifter::FlagBit::OF};
    return ir;
}

Lifter::IRInstruction JunkCodeGenerator::GenerateStackPivot(std::mt19937& rng) {
    Lifter::IRInstruction ir;
    ir.op = Lifter::IROp::Add;
    ir.resultValue = NextSSA();
    ir.inputs = {Lifter::Operand::Imm(rng(), 64), Lifter::Operand::Imm(0, 64)};
    return ir;
}

} // namespace IronLock::Modules::Obfuscation
