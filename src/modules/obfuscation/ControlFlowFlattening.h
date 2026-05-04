#pragma once
#include "../vm/lifter/IR.h"
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <functional>
#include <random>

namespace IronLock::Modules::Obfuscation {

// Control Flow Flattening - Core component for VMProtect-level protection
// Transforms structured CFG into state-machine based flattened graph

struct FlatteningConfig {
    uint32_t stateBits = 16;           // Number of bits for state variable
    uint32_t bogusBlocks = 5;          // Number of fake basic blocks to insert
    uint32_t opaquePredicates = 3;     // Number of opaque predicates
    bool addJunkHandlers = true;       // Insert junk code between transitions
    bool mutateState = true;           // Apply state mutation on transitions
};

struct FlattenedBlock {
    uint32_t originalId;
    uint32_t stateValue;
    std::vector<Lifter::IRInstruction> instructions;
    std::vector<uint32_t> successors;
    bool isBogus = false;
    bool isOpaque = false;
};

struct FlattenedFunction {
    Lifter::RegisterId stateRegister;
    uint32_t initialState;
    uint32_t exitState;
    std::unordered_map<uint32_t, FlattenedBlock> blocks;
    uint32_t dispatchBlockId;
    std::vector<uint32_t> stateTransitionTable;
};

class ControlFlowFlattener {
public:
    static FlattenedFunction Flatten(Lifter::LiftedFunction& fn, const FlatteningConfig& config);
    static std::vector<uint8_t> GenerateDispatchStub(const FlattenedFunction& flattened);
    
private:
    static uint32_t GenerateStateValue(std::mt19937& rng, uint32_t bits);
    static void InsertBogusBlocks(FlattenedFunction& flattened, const FlatteningConfig& config, std::mt19937& rng);
    static void InsertOpaquePredicates(FlattenedFunction& flattened, const FlatteningConfig& config, std::mt19937& rng);
    static void BuildDispatchBlock(FlattenedFunction& flattened);
    static void MutateStateTransitions(FlattenedFunction& flattened, std::mt19937& rng);
    static Lifter::IRInstruction GenerateStateCheck(uint32_t expectedState, Lifter::RegisterId stateReg);
    static Lifter::IRInstruction GenerateStateUpdate(uint32_t newState, Lifter::RegisterId stateReg);
    static std::vector<Lifter::IRInstruction> GenerateOpaquePredicateTrue(std::mt19937& rng);
    static std::vector<Lifter::IRInstruction> GenerateOpaquePredicateFalse(std::mt19937& rng);
    static std::vector<Lifter::IRInstruction> GenerateJunkCode(std::mt19937& rng);
};

// Opaque Predicate Generator
class OpaquePredicateGenerator {
public:
    enum class PredicateType : uint8_t {
        AlwaysTrue,
        AlwaysFalse,
        InvariantTrue,
        InvariantFalse,
        Mathematical,
        Bitwise
    };
    
    static std::vector<Lifter::IRInstruction> Generate(PredicateType type, std::mt19937& rng);
    static std::vector<uint8_t> GenerateMachineCode(PredicateType type, std::mt19937& rng);
    
private:
    static std::vector<Lifter::IRInstruction> GenerateMathematicalTrue(std::mt19937& rng);
    static std::vector<Lifter::IRInstruction> GenerateMathematicalFalse(std::mt19937& rng);
    static std::vector<Lifter::IRInstruction> GenerateBitwiseTrue(std::mt19937& rng);
    static std::vector<Lifter::IRInstruction> GenerateBitwiseFalse(std::mt19937& rng);
};

// Junk Code Generator
class JunkCodeGenerator {
public:
    static std::vector<Lifter::IRInstruction> GenerateJunk(size_t count, std::mt19937& rng);
    static std::vector<uint8_t> GenerateJunkBytes(size_t count, std::mt19937& rng);
    
private:
    static Lifter::IRInstruction GenerateDeadStore(std::mt19937& rng);
    static Lifter::IRInstruction GenerateNopSequence(std::mt19937& rng);
    static Lifter::IRInstruction GenerateFlagTrash(std::mt19937& rng);
    static Lifter::IRInstruction GenerateStackPivot(std::mt19937& rng);
};

} // namespace IronLock::Modules::Obfuscation
