#include "AntiDebug_User.h"
#include "../../core/Resolver.h"
#include "../../core/Syscalls.h"
#include "../../core/Hashing.h"
#include "../../core/Utils.h"
#include <winternl.h>
#include <intrin.h>

namespace IronLock::Modules::AntiDebug {

using namespace IronLock::Core;

bool CheckPEB() {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    // PEB.BeingDebugged and PEB.NtGlobalFlag (0x70)
    return (peb->BeingDebugged != 0) || (*(DWORD*)((BYTE*)peb + 0xBC) & 0x70);
}

bool CheckRemoteDebugger() {
    BOOL debugged = FALSE;
    NTSTATUS status = Syscalls::DoSyscall(Hashing::HashString("NtQueryInformationProcess"),
        (HANDLE)-1, 7, &debugged, sizeof(debugged), NULL);
    return (status == 0) && (debugged != FALSE);
}

bool CheckProcessDebugPort() {
    DWORD_PTR debugPort = 0;
    Syscalls::DoSyscall(Hashing::HashString("NtQueryInformationProcess"), (HANDLE)-1, 7, &debugPort, sizeof(debugPort), NULL);
    return debugPort != 0;
}

bool CheckInvalidHandle() {
    __try {
        Syscalls::DoSyscall(Hashing::HashString("NtClose"), (HANDLE)0xDEADBEEF);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
    return false;
}

bool CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    auto pGetThreadContext = Resolver::GetExport<decltype(&GetThreadContext)>(Hashing::HashStringW(L"kernel32.dll"), Hashing::HashString("GetThreadContext"));
    if (pGetThreadContext && pGetThreadContext(GetCurrentThread(), &ctx)) {
        return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
    }
    return false;
}

bool RunUserModeChecks() {
    bool result = false;
    result |= CheckPEB();
    result |= CheckRemoteDebugger();
    result |= CheckProcessDebugPort();
    result |= CheckInvalidHandle();
    result |= CheckHardwareBreakpoints();
    return result;
}

} // namespace IronLock::Modules::AntiDebug
