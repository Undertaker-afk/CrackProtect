#include "IronLock/ProtectionSDK.h"
#include "../../src/core/Syscalls.h"
#include "../../src/core/Audit.h"
#include "../../src/modules/anti_debug/AntiDebug_User.h"
#include "../../src/modules/anti_debug/AntiDebug_Kernel.h"
#include "../../src/modules/anti_vm/VMDetect.h"
#include "../../src/modules/sandbox/SandboxDetect.h"
#include "../../src/modules/network/NetworkProtection.h"
#include "../../src/modules/memory/Integrity.h"
#include "../../src/modules/tools/ToolDetect.h"

namespace IronLock {

static TripwireCallback g_Callback = nullptr;

bool ProtectionInit() {
    bool success = Core::Syscalls::Initialize();
    if (success) {
        // Feature 17: Anti-Attach Patching on Init
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
    bool safe = true;

    // Aggregated checks with Audit logging
    if (AntiDebug::IsDebuggerPresent()) safe = false;
    if (AntiDebug::CheckKernelDebugger()) safe = false;
    if (AntiVM::IsRunningInVM()) safe = false;
    if (Sandbox::IsRunningInSandbox()) safe = false;
    if (!Network::IsNetworkSafe()) safe = false;
    if (!Integrity::CheckSelfIntegrity()) safe = false;

    // Feature 5: Tool Detection integration
    if (Modules::Tools::RunAllToolChecks()) {
        Core::Audit::Log("Analysis Tool detected in background");
        safe = false;
    }

    if (!safe && g_Callback) {
        g_Callback(1);
    }
    return safe;
}

void RegisterTripwire(TripwireCallback callback) {
    g_Callback = callback;
}

} // namespace IronLock
