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

bool CheckSMBIOS() { return false; }

bool CheckRegistryKeys() {
    HKEY hKey;
    const wchar_t* keys[] = {
        L"HARDWARE\\Description\\System\\SystemBios\\VideoBiosVersion",
        L"SOFTWARE\\VMware, Inc.\\VMware Tools"
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
    return false;
}

bool CheckVMwareBackdoor() {
    return false;
}

bool CheckVBoxArtifacts() {
    return GetFileAttributesW(L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys") != INVALID_FILE_ATTRIBUTES;
}

bool CheckHyperV() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    return memcmp(&cpuInfo[1], "Microsoft Hv", 12) == 0;
}

bool RunAllVMChecks() {
    return CheckHypervisorBit() || CheckCPUID() || CheckDrivers() || CheckRegistryKeys() || CheckVBoxArtifacts() || CheckHyperV();
}

} // namespace IronLock::Modules::AntiVM
