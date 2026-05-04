#include "AntiDebug_Kernel.h"
#include "../../core/Syscalls.h"
#include "../../core/Hashing.h"
#include "../../core/Resolver.h"
#include <windows.h>

namespace IronLock::Modules::AntiDebug {

using namespace IronLock::Core;

bool CheckKernelDebugger() {
    // SharedUserData!KdDebuggerEnabled
    return *(BYTE*)0x7FFE02D4 & 0x1;
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

bool CheckKdDebuggerEnabled() {
    // Check KdDebuggerEnabled flag in ntdll or via syscall
    return false;
}

} // namespace IronLock::Modules::AntiDebug
