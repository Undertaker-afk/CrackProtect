#include "AntiDebug_Kernel.h"
#include "../../core/Syscalls.h"
#include "../../core/Hashing.h"
#include <windows.h>

namespace IronLock::Modules::AntiDebug {

using namespace IronLock::Core;

bool CheckKernelDebugger() {
    // KUSER_SHARED_DATA is at 0x7FFE0000
    // KdDebuggerEnabled is at offset 0x2D4
    return *(BYTE*)0x7FFE02D4 & 0x1;
}

bool CheckSystemKernelDebuggerInformation() {
    struct SYSTEM_KERNEL_DEBUGGER_INFORMATION {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerNotPresent;
    } info;

    typedef NTSTATUS(WINAPI* tNtQuerySystemInformation)(uint32_t, PVOID, ULONG, PULONG);
    // Note: Better to use Syscalls::DoSyscall for NtQuerySystemInformation
    NTSTATUS status = Syscalls::DoSyscall(Hashing::HashString("NtQuerySystemInformation"),
        35, // SystemKernelDebuggerInformation
        &info,
        sizeof(info),
        NULL);

    return (status == 0) && info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent;
}

} // namespace IronLock::Modules::AntiDebug
