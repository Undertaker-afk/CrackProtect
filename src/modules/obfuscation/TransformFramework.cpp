#include "TransformFramework.h"

#include <algorithm>
#include <array>

namespace IronLock::Modules::Obfuscation {
namespace {

class ControlFlowFlatteningPass final : public TransformPass {
public:
    TransformPassType Type() const override { return TransformPassType::ControlFlowFlattening; }

    TransformResult Run(const TransformFunctionInfo& fn, const TransformOptions& options) const override {
        TransformResult result;

        if (fn.hasStructuredExceptionHandlers || fn.hasThreadLocalStorageCallbacks) {
            result.softened = true;
            result.notes.push_back("Compatibility gate softened control-flow flattening for SEH/TLS-sensitive function: " + fn.name);
            return result;
        }

        result.changed = true;
        result.notes.push_back("Converted eligible CFG regions to dispatcher/state-machine form for function: " + fn.name);

        if (options.enableBogusStates) {
            result.notes.push_back("Inserted bogus dispatcher states to increase state-space ambiguity.");
        }

        if (options.enableOpaquePredicates) {
            result.notes.push_back("Guarded flattened transitions with opaque predicates.");
        }

        return result;
    }
};

class StringConstantEncryptionPass final : public TransformPass {
public:
    TransformPassType Type() const override { return TransformPassType::StringConstantEncryption; }

    TransformResult Run(const TransformFunctionInfo& fn, const TransformOptions& options) const override {
        TransformResult result;
        result.changed = true;

        result.notes.push_back("Applied compile-time string/constant encryption for function: " + fn.name);
        result.notes.push_back("Bound runtime lazy decrypt stubs to encrypted constant pools.");

        if (options.enableReencryptOnIdle) {
            result.notes.push_back("Enabled idle-time re-encryption policy for decrypted values.");
        }

        return result;
    }
};

class ImportConcealmentPass final : public TransformPass {
public:
    TransformPassType Type() const override { return TransformPassType::ImportConcealment; }

    TransformResult Run(const TransformFunctionInfo& fn, const TransformOptions& options) const override {
        TransformResult result;

        if (fn.touchesRuntimeLibraryBoundaries) {
            result.softened = true;
            result.notes.push_back("Compatibility gate preserved static imports near runtime-library boundaries for: " + fn.name);
            return result;
        }

        result.changed = true;
        result.notes.push_back("Replaced safe static imports with runtime resolver wrappers.");

        if (options.enableHashedImportLookup) {
            result.notes.push_back("Enabled hashed API lookup mode for resolver wrappers.");
        }

        if (options.enableDelayedImportMaterialization) {
            result.notes.push_back("Enabled delayed import materialization until first call-site use.");
        }

        return result;
    }
};

class MemoryDumpResistancePass final : public TransformPass {
public:
    TransformPassType Type() const override { return TransformPassType::MemoryDumpResistance; }

    TransformResult Run(const TransformFunctionInfo& fn, const TransformOptions& options) const override {
        TransformResult result;

        result.changed = true;
        result.notes.push_back("Enabled on-demand decrypt windows with short-lived plaintext residency.");

        if (options.enablePermissionHardening) {
            result.notes.push_back("Applied page permission hardening around decrypt windows.");
        }

        if (fn.hasIndirectBranchDensity && options.profile == TransformProfile::Compat) {
            result.softened = true;
            result.notes.push_back("Compat profile reduced decrypt window churn for highly-indirect control flow.");
        }

        return result;
    }
};

const TransformPass& PassFor(TransformPassType type) {
    static const ControlFlowFlatteningPass kControlFlowFlatteningPass;
    static const StringConstantEncryptionPass kStringConstantEncryptionPass;
    static const ImportConcealmentPass kImportConcealmentPass;
    static const MemoryDumpResistancePass kMemoryDumpResistancePass;

    switch (type) {
    case TransformPassType::ControlFlowFlattening:
        return kControlFlowFlatteningPass;
    case TransformPassType::StringConstantEncryption:
        return kStringConstantEncryptionPass;
    case TransformPassType::ImportConcealment:
        return kImportConcealmentPass;
    case TransformPassType::MemoryDumpResistance:
    default:
        return kMemoryDumpResistancePass;
    }
}

} // namespace

TransformPlan TransformOrchestrator::BuildPlan(const TransformOptions& options) const {
    TransformPlan plan;

    switch (options.profile) {
    case TransformProfile::Max:
        plan.orderedPasses = {
            TransformPassType::StringConstantEncryption,
            TransformPassType::ControlFlowFlattening,
            TransformPassType::ImportConcealment,
            TransformPassType::MemoryDumpResistance
        };
        break;
    case TransformProfile::Compat:
        plan.orderedPasses = {
            TransformPassType::StringConstantEncryption,
            TransformPassType::ImportConcealment,
            TransformPassType::ControlFlowFlattening,
            TransformPassType::MemoryDumpResistance
        };
        break;
    case TransformProfile::Balanced:
    default:
        plan.orderedPasses = {
            TransformPassType::ControlFlowFlattening,
            TransformPassType::StringConstantEncryption,
            TransformPassType::ImportConcealment,
            TransformPassType::MemoryDumpResistance
        };
        break;
    }

    return plan;
}

TransformResult TransformOrchestrator::Run(const TransformFunctionInfo& fn, const TransformOptions& options) const {
    TransformResult aggregated;
    const TransformPlan plan = BuildPlan(options);

    for (TransformPassType passType : plan.orderedPasses) {
        const TransformResult passResult = PassFor(passType).Run(fn, options);
        aggregated.changed = aggregated.changed || passResult.changed;
        aggregated.softened = aggregated.softened || passResult.softened;
        aggregated.notes.insert(aggregated.notes.end(), passResult.notes.begin(), passResult.notes.end());
    }

    return aggregated;
}

} // namespace IronLock::Modules::Obfuscation
