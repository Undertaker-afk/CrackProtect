#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace IronLock::Modules::Obfuscation {

enum class TransformPassType : uint8_t {
    ControlFlowFlattening = 0,
    StringConstantEncryption,
    ImportConcealment,
    MemoryDumpResistance
};

enum class TransformProfile : uint8_t {
    Balanced = 0,
    Max,
    Compat
};

struct TransformFunctionInfo {
    std::string name;
    bool hasStructuredExceptionHandlers{false};
    bool hasThreadLocalStorageCallbacks{false};
    bool touchesRuntimeLibraryBoundaries{false};
    bool hasIndirectBranchDensity{false};
};

struct TransformOptions {
    TransformProfile profile{TransformProfile::Balanced};
    bool enableBogusStates{true};
    bool enableOpaquePredicates{true};
    bool enableReencryptOnIdle{true};
    bool enableHashedImportLookup{false};
    bool enableDelayedImportMaterialization{true};
    bool enablePermissionHardening{true};
};

struct TransformPlan {
    std::vector<TransformPassType> orderedPasses;
};

struct TransformResult {
    bool changed{false};
    bool softened{false};
    std::vector<std::string> notes;
};

class TransformPass {
public:
    virtual ~TransformPass() = default;
    virtual TransformPassType Type() const = 0;
    virtual TransformResult Run(const TransformFunctionInfo& fn, const TransformOptions& options) const = 0;
};

class TransformOrchestrator {
public:
    TransformPlan BuildPlan(const TransformOptions& options) const;
    TransformResult Run(const TransformFunctionInfo& fn, const TransformOptions& options) const;
};

} // namespace IronLock::Modules::Obfuscation
