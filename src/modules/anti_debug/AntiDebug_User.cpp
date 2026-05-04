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

bool CheckSoftwareBreakpoints() {
    PVOID base = Resolver::GetModuleBase(0);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            BYTE* start = (BYTE*)base + section[i].VirtualAddress;
            for (DWORD j = 0; j < section[i].Misc.VirtualSize; j++) {
                if (start[j] == 0xCC) return true;
            }
        }
    }
    return false;
}

bool CheckTimingDelta() {
    uint64_t t1 = __rdtsc();
    for (int i = 0; i < 100; ++i) __nop();
    uint64_t t2 = __rdtsc();
    return (t2 - t1) > 0x10000;
}

bool CheckOutputDebugString() {
    SetLastError(0);
    OutputDebugStringA("IronLock");
    return GetLastError() != 0;
}

bool CheckGuardPage() {
    SYSTEM_INFO si; GetSystemInfo(&si);
    LPVOID lpPage = VirtualAlloc(NULL, si.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!lpPage) return false;
    DWORD dwOldProtect;
    VirtualProtect(lpPage, si.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &dwOldProtect);
    __try { *(BYTE*)lpPage = 1; }
    __except (EXCEPTION_EXECUTE_HANDLER) { VirtualFree(lpPage, 0, MEM_RELEASE); return false; }
    VirtualFree(lpPage, 0, MEM_RELEASE);
    return true;
}

bool CheckTrapFlag() {
    __try {
#ifdef _WIN64
        // Logic for x64 TF check would go in assembly
        return false;
#else
        __asm { pushfd; or dword ptr [esp], 0x100; popfd; nop; }
#endif
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    return true;
}

bool CheckParentProcess() {
    // Basic heuristic: Is parent 'explorer.exe' or 'cmd.exe'?
    return false;
}

bool CheckSeDebugPrivilege() {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        // Logic to check SE_DEBUG_NAME
        CloseHandle(hToken);
    }
    return false;
}

bool CheckThreadHideFromDebugger() {
    // NtSetInformationThread with ThreadHideFromDebugger
    return (Syscalls::DoSyscall(Hashing::HashString("NtSetInformationThread"), GetCurrentThread(), 0x11, NULL, 0) != 0);
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
    res |= CheckHeapFlags();
    res |= CheckTimingDelta();
    res |= CheckSoftwareBreakpoints();
    return res;
}

} // namespace IronLock::Modules::AntiDebug
