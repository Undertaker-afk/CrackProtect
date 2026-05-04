#include "IronLock/ProtectionSDK.h"
#include "core/Syscalls.h"
#include "core/Audit.h"
#include "core/PolicyEngine.h"
#include "modules/anti_debug/AntiDebug_User.h"
#include "modules/anti_debug/AntiDebug_Kernel.h"
#include "modules/anti_vm/VMDetect.h"
#include "modules/sandbox/SandboxDetect.h"
#include "modules/network/NetworkProtection.h"
#include "modules/memory/Integrity.h"
#include "modules/tools/ToolDetect.h"
#include "modules/vm/VirtualMachine.h"
#include <vector>
#include <ctime>
#include <string>

namespace IronLock {

static TripwireCallback g_Callback = nullptr;

bool ProtectionInit() {
    bool success = Core::Syscalls::Initialize();
    if (success) {

    Modules::VM::VirtualMachine::RuntimeProfile vmProfile{};
    for (size_t i = 0; i < vmProfile.decodeTable.size(); ++i) vmProfile.decodeTable[i] = static_cast<uint8_t>(i);
    vmProfile.keySalt = {0xA5311E4Du, 0x9BC1022Fu, 0x74CC55A1u, 0x11EE0D99u};
    success = Modules::VM::VirtualMachine::InitializeRuntime(vmProfile) && success;
    Core::PolicyEngine::Initialize("balanced");
    Modules::Memory::PatchAntiAttach();
    Core::Audit::Log("IronLock SDK Initialized Successfully.");
    }
    return success;
}

bool AntiDebug::IsDebuggerPresent() {
    bool detected = Modules::AntiDebug::RunUserModeChecks();
    if (detected) Core::Audit::Log("Debugger Detected via User-Mode Checks");
    return detected;
}

bool AntiDebug::CheckKernelDebugger() {
    bool detected = Modules::AntiDebug::CheckKernelDebugger();
    if (detected) Core::Audit::Log("Kernel Debugger Detected");
    return detected;
}

bool AntiVM::IsRunningInVM() {
    bool detected = Modules::AntiVM::RunAllVMChecks();
    if (detected) Core::Audit::Log("Execution in Virtual Machine Detected");
    return detected;
}

bool Sandbox::IsRunningInSandbox() {
    bool detected = Modules::Sandbox::RunAllSandboxChecks();
    if (detected) Core::Audit::Log("Execution in Sandbox Detected");
    return detected;
}

bool Network::IsNetworkSafe() {
    bool unsafe = Modules::Network::RunAllNetworkChecks();
    if (unsafe) Core::Audit::Log("Network Interception/VPN Detected");
    return !unsafe;
}

bool Network::IsVpnActive() {
    return Modules::Network::IsVpnPresent();
}

bool Integrity::CheckSelfIntegrity() {
    bool safe = Modules::Memory::VerifySectionIntegrity() && !Modules::Memory::DetectHooks();
    if (!safe) Core::Audit::Log("Integrity Violation: .text section or API hooks found");
    return safe;
}

bool IsEnvironmentSafe() {
    std::vector<Core::Evidence> evidence;

    const bool userDbg = AntiDebug::IsDebuggerPresent();
    evidence.push_back({"anti_debug.user", userDbg, 0.90, 0.95, userDbg ? "User-mode debugger indicators present" : "No user-mode debugger evidence"});

    const bool kernelDbg = AntiDebug::CheckKernelDebugger();
    evidence.push_back({"anti_debug.kernel", kernelDbg, 1.00, 0.90, kernelDbg ? "Kernel debugger state detected" : "Kernel debugger checks are clean"});

    const bool vmDetected = AntiVM::IsRunningInVM();
    evidence.push_back({"anti_vm", vmDetected, 0.65, 0.75, vmDetected ? "Virtualized environment fingerprints detected" : "No virtualization fingerprints"});

    const bool sandboxDetected = Sandbox::IsRunningInSandbox();
    evidence.push_back({"sandbox", sandboxDetected, 0.75, 0.80, sandboxDetected ? "Sandbox artifacts detected" : "No sandbox artifacts"});

    const bool networkUnsafe = !Network::IsNetworkSafe();
    evidence.push_back({"network", networkUnsafe, 0.50, 0.70, networkUnsafe ? "Network interception/VPN evidence detected" : "Network posture appears safe"});

    const bool integrityUnsafe = !Integrity::CheckSelfIntegrity();
    evidence.push_back({"integrity", integrityUnsafe, 0.95, 0.95, integrityUnsafe ? "Integrity violation or API hooks detected" : "Code integrity checks passed"});

    const bool toolsDetected = Modules::Tools::RunAllToolChecks();
    if (toolsDetected) {
        Core::Audit::Log("Analysis Tool detected in background");
    }
    evidence.push_back({"analysis_tools", toolsDetected, 0.80, 0.85, toolsDetected ? "Analysis tools running in background" : "No analysis tools detected"});

    Core::EvaluationContext ctx{};
    ctx.highValueTarget = integrityUnsafe || kernelDbg;
    ctx.userFacingCriticalPath = !toolsDetected;

    const Core::PolicyDecision decision = Core::PolicyEngine::Evaluate(evidence, ctx);

    Core::Audit::LogEvent({
        "policy.decision",
        "Environment policy evaluation completed",
        "policy=" + decision.policy + ",risk=" + std::to_string(decision.riskScore) + ",confidence=" + std::to_string(decision.confidence) +
            ",tier=" + std::to_string(static_cast<int>(decision.tier)) + ",deferred=" + (decision.deferred ? "true" : "false") +
            ",accelerated=" + (decision.accelerated ? "true" : "false"),
        static_cast<uint64_t>(std::time(nullptr))
    });

    const bool safe = decision.tier == Core::ResponseTier::NONE || decision.tier == Core::ResponseTier::MONITOR;
    if (!safe && g_Callback) {
        g_Callback(static_cast<int>(decision.tier));
    }

    return safe;
}

void RegisterTripwire(TripwireCallback callback) {
    g_Callback = callback;
}

} // namespace IronLock
