#include "IronLock/ProtectionSDK.h"
#include "core/Syscalls.h"
#include "core/Audit.h"
#include "modules/anti_debug/AntiDebug_User.h"
#include "modules/anti_debug/AntiDebug_Kernel.h"
#include "modules/anti_vm/VMDetect.h"
#include "modules/sandbox/SandboxDetect.h"
#include "modules/network/NetworkProtection.h"
#include "modules/memory/Integrity.h"
#include "modules/tools/ToolDetect.h"
#include "modules/vm/VirtualMachine.h"

namespace IronLock {

static TripwireCallback g_Callback = nullptr;

bool ProtectionInit() {
    bool success = Core::Syscalls::Initialize();
    if (success) {

    Modules::VM::VirtualMachine::RuntimeProfile vmProfile{};
    for (size_t i = 0; i < vmProfile.decodeTable.size(); ++i) vmProfile.decodeTable[i] = static_cast<uint8_t>(i);
    vmProfile.keySalt = {0xA5311E4Du, 0x9BC1022Fu, 0x74CC55A1u, 0x11EE0D99u};
    success = Modules::VM::VirtualMachine::InitializeRuntime(vmProfile) && success;
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

    if (AntiDebug::IsDebuggerPresent()) safe = false;
    if (AntiDebug::CheckKernelDebugger()) safe = false;
    if (AntiVM::IsRunningInVM()) safe = false;
    if (Sandbox::IsRunningInSandbox()) safe = false;
    if (!Network::IsNetworkSafe()) safe = false;
    if (!Integrity::CheckSelfIntegrity()) safe = false;

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
