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
    return peb->BeingDebugged != 0;
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

bool CheckProcessDebugFlags() {
    DWORD debugFlags = 0;
    Syscalls::DoSyscall(Hashing::HashString("NtQueryInformationProcess"), (HANDLE)-1, 0x1F, &debugFlags, sizeof(debugFlags), NULL);
    return debugFlags == 0;
}

bool CheckProcessDebugObject() {
    HANDLE hDebugObj = NULL;
    Syscalls::DoSyscall(Hashing::HashString("NtQueryInformationProcess"), (HANDLE)-1, 0x1E, &hDebugObj, sizeof(hDebugObj), NULL);
    return hDebugObj != NULL;
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

bool CheckHeapFlags() {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PVOID heap = peb->ProcessHeap;
    // Flags and ForceFlags are at different offsets for x64/x86
    // This is a simplified check
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

bool CheckSoftwareBreakpoints() {
    // Scan own code for 0xCC (INT 3)
    PVOID base = Resolver::GetModuleBase(0);
    // Logic to scan... simplified here
    return false;
}

bool CheckTimingDelta() {
    uint64_t t1 = __rdtsc();
    for(int i=0; i<100; ++i) __nop();
    uint64_t t2 = __rdtsc();
    return (t2 - t1) > 0x10000;
}

bool CheckOutputDebugString() {
    SetLastError(0);
    OutputDebugStringA("IronLock");
    return GetLastError() != 0;
}

bool CheckGuardPage() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    LPVOID lpPage = VirtualAlloc(NULL, si.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!lpPage) return false;

    DWORD dwOldProtect;
    if (!VirtualProtect(lpPage, si.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &dwOldProtect)) return false;

    __try {
        *(BYTE*)lpPage = 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        VirtualFree(lpPage, 0, MEM_RELEASE);
        return false; // Debugger would have handled the exception
    }
    VirtualFree(lpPage, 0, MEM_RELEASE);
    return true;
}

bool CheckTrapFlag() {
    __try {
        __asm {
            pushfd
            or dword ptr [esp], 0x100
            popfd
            nop
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

bool CheckParentProcess() {
    // Check if parent is explorer.exe
    return false;
}

bool CheckSeDebugPrivilege() {
    return false;
}

bool CheckThreadHideFromDebugger() {
    return false;
}

bool CheckDebugApiHooks() {
    return false;
}

bool RunUserModeChecks() {
    bool res = false;
    res |= CheckPEB();
    res |= CheckRemoteDebugger();
    res |= CheckProcessDebugPort();
    res |= CheckProcessDebugFlags();
    res |= CheckInvalidHandle();
    res |= CheckHardwareBreakpoints();
    res |= CheckTimingDelta();
    return res;
}

} // namespace IronLock::Modules::AntiDebug
