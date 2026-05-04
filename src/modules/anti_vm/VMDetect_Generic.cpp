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
    if (s == "VMwareVMware" || s == "VBoxVBoxVBox" || s == "KVMKVMKVM" || s == "Microsoft Hv" || s == "XenVMMXenVMM")
        return true;
    return false;
}

bool CheckVMwareBackdoor() {
    __try {
        return CheckVMwareBackdoorInternal();
    } __except(1) {
        return false;
    }
}

bool CheckDrivers() {
    const std::vector<std::wstring> drivers = {
        L"VBoxGuest.sys", L"VBoxMouse.sys", L"VBoxSF.sys", L"VBoxVideo.sys",
        L"vmmouse.sys", L"vmusb.sys", L"vm3dmp.sys", L"vmhgfs.sys"
    };
    for (const auto& d : drivers) {
        if (GetFileAttributesW((L"C:\\Windows\\System32\\drivers\\" + d).c_str()) != INVALID_FILE_ATTRIBUTES)
            return true;
    }
    return false;
}

bool RunAllVMChecks() {
    return CheckHypervisorBit() || CheckCPUID() || CheckDrivers() || CheckVMwareBackdoor();
}

} // namespace IronLock::Modules::AntiVM
