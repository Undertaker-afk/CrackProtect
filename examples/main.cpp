#include "IronLock/ProtectionSDK.h"
#include <iostream>
#include <iomanip>

void OnThreatDetected(int reason) {
    std::cout << "[!] IronLock Tripwire Triggered! Reason: " << reason << std::endl;
}

int main() {
    std::cout << "--- IronLock Protection SDK Demo ---" << std::endl;

    if (!IronLock::ProtectionInit()) {
        std::cerr << "[-] Failed to initialize IronLock." << std::endl;
        return 1;
    }

    IronLock::RegisterTripwire(OnThreatDetected);

    std::cout << "[*] Running environment checks..." << std::endl;

    bool isSafe = IronLock::IsEnvironmentSafe();

    std::cout << "------------------------------------" << std::endl;
    std::cout << "Debugger Present: " << (IronLock::AntiDebug::IsDebuggerPresent() ? "YES" : "NO") << std::endl;
    std::cout << "Kernel Debugger:  " << (IronLock::AntiDebug::CheckKernelDebugger() ? "YES" : "NO") << std::endl;
    std::cout << "In VM:            " << (IronLock::AntiVM::IsRunningInVM() ? "YES" : "NO") << std::endl;
    std::cout << "In Sandbox:       " << (IronLock::Sandbox::IsRunningInSandbox() ? "YES" : "NO") << std::endl;
    std::cout << "Network Safe:     " << (IronLock::Network::IsNetworkSafe() ? "YES" : "NO") << std::endl;
    std::cout << "Self Integrity:   " << (IronLock::Integrity::CheckSelfIntegrity() ? "YES" : "NO") << std::endl;
    std::cout << "------------------------------------" << std::endl;

    if (isSafe) {
        std::cout << "[+] Environment is safe. Proceeding..." << std::endl;
    } else {
        std::cout << "[!] Environment is UNSAFE. Taking protective action..." << std::endl;
        // The SDK would normally trigger responses here
    }

    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}
