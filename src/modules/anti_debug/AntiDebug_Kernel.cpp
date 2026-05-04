#include "AntiDebug_Kernel.h"
#include "../../core/Syscalls.h"
#include "../../core/Hashing.h"
#include <windows.h>

namespace IronLock::Modules::AntiDebug {

using namespace IronLock::Core;

bool CheckKernelDebugger() {
    // SharedUserData!KdDebuggerEnabled
    return *(BYTE*)0x7FFE02D4 & 0x1;
}

bool CheckSharedUserData() {
    // Another check on SharedUserData
    return (*(ULONG*)0x7FFE02D0 != 0);
}

bool CheckSystemKernelDebuggerInformation() {
    struct SYSTEM_KERNEL_DEBUGGER_INFORMATION {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerNotPresent;
    } info;

    NTSTATUS status = Syscalls::DoSyscall(Hashing::HashString("NtQuerySystemInformation"),
        35, // SystemKernelDebuggerInformation
        &info,
        sizeof(info),
        NULL);

    return (status == 0) && info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent;
}

} // namespace IronLock::Modules::AntiDebug
