#include "VMDetect.h"
#include "../../core/Utils.h"
#include <intrin.h>
#include <windows.h>
#include <vector>
#include <string>

extern "C" bool CheckVMwareBackdoorInternal();

namespace IronLock::Modules::AntiVM {

bool CheckHypervisorBit() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0;
}

bool CheckCPUID() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    char vendor[13];
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    vendor[12] = '\0';
    std::string s(vendor);
    return (s == "VMwareVMware" || s == "VBoxVBoxVBox" || s == "KVMKVMKVM" || s == "Microsoft Hv" || s == "XenVMMXenVMM");
}

bool CheckSMBIOS() {
    // Basic SMBIOS artifact check in registry
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\Description\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t vendor[256];
        DWORD size = sizeof(vendor);
        if (RegQueryValueExW(hKey, L"SystemManufacturer", NULL, NULL, (LPBYTE)vendor, &size) == ERROR_SUCCESS) {
            std::wstring s(vendor);
            if (s.find(L"VMware") != std::wstring::npos || s.find(L"VirtualBox") != std::wstring::npos) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool CheckRegistryKeys() {
    HKEY hKey;
    const wchar_t* keys[] = {
        L"HARDWARE\\Description\\System\\SystemBios\\VideoBiosVersion",
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions"
    };
    for (const auto& k : keys) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    return false;
}

bool CheckDrivers() {
    if (GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys") != INVALID_FILE_ATTRIBUTES) return true;
    if (GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\vmmouse.sys") != INVALID_FILE_ATTRIBUTES) return true;
    if (GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\vboxguest.sys") != INVALID_FILE_ATTRIBUTES) return true;
    return false;
}

bool CheckVMwareBackdoor() {
    __try {
        return CheckVMwareBackdoorInternal();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool CheckVBoxArtifacts() {
    return GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys") != INVALID_FILE_ATTRIBUTES;
}

bool CheckHyperV() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) && (cpuInfo[3] & (1 << 30)); // Placeholder for actual Hv check
}

bool RunAllVMChecks() {
    return CheckHypervisorBit() || CheckCPUID() || CheckDrivers() || CheckRegistryKeys() || CheckSMBIOS() || CheckVMwareBackdoor();
}

} // namespace IronLock::Modules::AntiVM
