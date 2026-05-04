#include "IronLock/ProtectionSDK.h"
#include <iostream>
#include <string>
#include <windows.h>

// IronLock TUI Demo Loader
// Demonstrates how to use the SDK in a real-world application loader scenario.

void OnThreatDetected(int reason) {
    std::cout << "\n[!] SECURITY VIOLATION DETECTED (Code: " << reason << ")" << std::endl;
    std::cout << "[!] IronLock is taking protective action..." << std::endl;
    // In a real loader, we would exit or trigger a logic bomb here.
    Sleep(2000);
    exit(reason);
}

bool PerformLogin() {
    std::string user, pass;
    std::cout << "--- IronLock Secure Loader ---" << std::endl;
    std::cout << "Username: ";
    std::cin >> user;
    std::cout << "Password: ";
    std::cin >> pass;

    // Simulate server-side check
    if (user == "admin" && pass == "ironlock2024") {
        std::cout << "[+] Login successful." << std::endl;
        return true;
    }
    std::cout << "[-] Invalid credentials." << std::endl;
    return false;
}

int main() {
    // 1. Initialize IronLock SDK
    if (!IronLock::ProtectionInit()) {
        std::cerr << "[-] Failed to initialize IronLock Protection." << std::endl;
        return 1;
    }

    // 2. Register security callback
    IronLock::RegisterTripwire(OnThreatDetected);

    // 3. Initial environment sweep
    std::cout << "[*] IronLock: Performing environment sweep..." << std::endl;
    if (!IronLock::IsEnvironmentSafe()) {
        // SDK will call OnThreatDetected
        return 1;
    }

    // 4. Application Logic
    if (PerformLogin()) {
        std::cout << "[*] Loading protected application module..." << std::endl;

        // Continuous background checks
        if (!IronLock::IsEnvironmentSafe()) return 1;

        std::cout << "[+] Application running under IronLock protection." << std::endl;
        std::cout << "Press ENTER to unload." << std::endl;
        std::cin.ignore();
        std::cin.get();
    }

    return 0;
}
