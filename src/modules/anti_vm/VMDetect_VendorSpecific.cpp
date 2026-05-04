#include "VMDetect.h"
#include <intrin.h>
#include <windows.h>
#include <cstring>

namespace IronLock::Modules::AntiVM {

// VMware-specific detection techniques
bool CheckVMwareSpecific() {
    // Check for VMware CPUID leaf
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
    if (strcmp(vendor, "VMwareVMware") == 0) {
        return true;
    }
    
    // Check VMware backdoor I/O port
    bool vmwareDetected = false;
    __try {
        uint64_t result;
        uint32_t eax = 0x564D5868;  // VMXh
        uint32_t ecx = 0x0A;         // Get version
        uint32_t ebx = 0;
        uint32_t edi = 0;
        
        __asm {
            push rbx
            push rdi
            mov rax, rcx
            mov rbx, rdx
            mov rcx, r8
            mov rdx, r9
            pop rdi
            pop rbx
        }
        
        // Alternative: use IN instruction to check VMware IO port
        // This is simplified - real impl would use __outbyte
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Exception means not running under VMware
    }
    
    return vmwareDetected;
}

// VirtualBox-specific detection
bool CheckVirtualBoxSpecific() {
    // Check for VirtualBox CPUID signature
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
    if (strstr(vendor, "VBoxVBoxVBox") != nullptr) {
        return true;
    }
    
    // Check for VirtualBox-specific ACPI tables
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                      L"HARDWARE\\ACPI\\FADT\\VBOX__", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
                      L"HARDWARE\\ACPI\\RSDT\\VBOX__", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    
    // Check for VirtualBox MAC address prefix (08:00:27)
    HMODULE hIpHelp = LoadLibraryW(L"iphlpapi.dll");
    if (hIpHelp) {
        // Simplified - real impl would enumerate network adapters
        FreeLibrary(hIpHelp);
    }
    
    return false;
}

// Hyper-V specific detection
bool CheckHyperVSpecific() {
    // Check for Hyper-V CPUID signature  
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
    if (strcmp(vendor, "Microsoft Hv") == 0) {
        return true;
    }
    
    // Check hypervisor feature flags
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {  // Hypervisor present bit
        // Additional Hyper-V specific checks
        __cpuid(cpuInfo, 0x40000001);
        // Check for Hyper-V features in EAX
        
        return true;
    }
    
    // Check for Hyper-V services
    if (GetFileAttributesW(L"C:\\Windows\\System32\\vmic.exe") != INVALID_FILE_ATTRIBUTES) {
        return true;
    }
    
    return false;
}

// KVM/QEMU specific detection
bool CheckKVMSpecific() {
    // Check for KVM CPUID signature
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
    if (strcmp(vendor, "KVMKVMKVM") == 0) {
        return true;
    }
    
    // Check for QEMU-specific hardware IDs
    HKEY hKey;
    const wchar_t* qemuPaths[] = {
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskQEMU"
    };
    
    for (const auto& path : qemuPaths) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t identifier[256];
            DWORD size = sizeof(identifier);
            if (RegQueryValueExW(hKey, L"Identifier", NULL, NULL, 
                                 reinterpret_cast<LPBYTE>(identifier), &size) == ERROR_SUCCESS) {
                if (wcsstr(identifier, L"QEMU") != nullptr) {
                    RegCloseKey(hKey);
                    return true;
                }
            }
            RegCloseKey(hKey);
        }
    }
    
    return false;
}

// Xen specific detection
bool CheckXenSpecific() {
    // Check for Xen CPUID signature
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
    if (strcmp(vendor, "XenVMMXenVMM") == 0) {
        return true;
    }
    
    return false;
}

// Parallels specific detection
bool CheckParallelsSpecific() {
    // Check for Parallels CPUID signature
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
    if (strstr(vendor, "lrpepyh vr") != nullptr) {  // Parallels signature reversed
        return true;
    }
    
    // Check for Parallels tools
    if (GetFileAttributesW(L"C:\\Program Files\\Parallels\\Parallels Tools\\prl_tools.exe") 
        != INVALID_FILE_ATTRIBUTES) {
        return true;
    }
    
    return false;
}

bool RunAllVMChecks() {
    return CheckHypervisorBit() || 
           CheckCPUID() || 
           CheckDrivers() || 
           CheckRegistryKeys() || 
           CheckSMBIOS() ||
           CheckVMwareBackdoor() ||
           CheckVMwareSpecific() ||
           CheckVirtualBoxSpecific() ||
           CheckHyperVSpecific() ||
           CheckKVMSpecific() ||
           CheckXenSpecific() ||
           CheckParallelsSpecific();
}

} // namespace IronLock::Modules::AntiVM
