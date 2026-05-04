#include "AntiDebug_User.h"
#include "../../core/Resolver.h"
#include "../../core/Syscalls.h"
#include "../../core/Hashing.h"
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
    Syscalls::DoSyscall(Hashing::HashString("NtQueryInformationProcess"), (HANDLE)-1, 7, &debugged, sizeof(debugged), NULL);
    return debugged != FALSE;
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
    // Flags and ForceFlags in DefaultHeap
    PVOID heap = peb->ProcessHeap;
    DWORD flags = *(DWORD*)((BYTE*)heap + 0x70);
    DWORD forceFlags = *(DWORD*)((BYTE*)heap + 0x74);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
    PVOID heap = peb->ProcessHeap;
    DWORD flags = *(DWORD*)((BYTE*)heap + 0x10);
    DWORD forceFlags = *(DWORD*)((BYTE*)heap + 0x14);
#endif
    return (flags & ~HEAP_GROWABLE) || (forceFlags != 0);
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

bool CheckTimingDelta() {
    uint64_t t1 = __rdtsc();
    for (int i = 0; i < 100; ++i) __nop();
    uint64_t t2 = __rdtsc();
    return (t2 - t1) > 0x10000;
}

bool RunUserModeChecks() {
    bool res = false;
    res |= CheckPEB();
    res |= CheckRemoteDebugger();
    res |= CheckProcessDebugPort();
    res |= CheckProcessDebugFlags();
    res |= CheckInvalidHandle();
    res |= CheckHardwareBreakpoints();
    res |= CheckHeapFlags();
    res |= CheckTimingDelta();
    return res;
}

} // namespace IronLock::Modules::AntiDebug
