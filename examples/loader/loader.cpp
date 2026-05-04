#include "IronLock/ProtectionSDK.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <vector>

// IronLock TUI Loader v1.2
// Comprehensive logging of security checks

void LogCheck(const std::string& name, bool detected) {
    std::cout << "[*] Check: " << name << " -> ";
    if (detected) {
        std::cout << "\033[1;31m[TAMPERED]\033[0m" << std::endl;
    } else {
        std::cout << "\033[1;32m[SAFE]\033[0m" << std::endl;
    }
}

void OnThreatDetected(int reason) {
    std::cout << "\n[!] SECURITY VIOLATION DETECTED (Code: " << reason << ")" << std::endl;
    exit(reason);
}

int main() {
    std::cout << "--- IronLock Secure Loader v1.2 ---" << std::endl;

    if (!IronLock::ProtectionInit()) {
        std::cerr << "[-] SDK Init Failed." << std::endl;
        return 1;
    }

    IronLock::RegisterTripwire(OnThreatDetected);

    std::cout << "[*] Running detailed security sweep..." << std::endl;

    LogCheck("User Debugger", IronLock::AntiDebug::IsDebuggerPresent());
    LogCheck("Kernel Debugger", IronLock::AntiDebug::CheckKernelDebugger());
    LogCheck("Virtual Machine", IronLock::AntiVM::IsRunningInVM());
    LogCheck("Sandbox Env", IronLock::Sandbox::IsRunningInSandbox());
    LogCheck("Network Proxy", !IronLock::Network::IsNetworkSafe());
    LogCheck("Self Integrity", !IronLock::Integrity::CheckSelfIntegrity());

    if (!IronLock::IsEnvironmentSafe()) {
        std::cout << "\033[1;31m[-] Environment is UNSAFE. Exiting.\033[0m" << std::endl;
        return 1;
    }

    std::string user, pass;
    std::cout << "\nUsername: "; std::cin >> user;
    std::cout << "Password: "; std::cin >> pass;

    if (user == "admin" && pass == "ironlock2024") {
        std::cout << "[+] Protected application launched." << std::endl;
        std::cout << "Press ENTER to unload." << std::endl;
        std::cin.ignore(); std::cin.get();
    }

    return 0;
}
