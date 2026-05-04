#include "Integrity.h"
#include "../../core/Hashing.h"
#include "../../core/Resolver.h"
#include "../../core/Syscalls.h"
#include <vector>
#include <tlhelp32.h>

namespace IronLock::Modules::Memory {

using namespace IronLock::Core;

#pragma section(".il_int1", read, write)
#pragma section(".il_int2", read, write)
#pragma section(".il_int3", read, write)

__declspec(allocate(".il_int1")) volatile uint32_t g_TextHash1 = 0xAAAAAAAA;
__declspec(allocate(".il_int2")) volatile uint32_t g_TextHash2 = 0xAAAAAAAA;
__declspec(allocate(".il_int3")) volatile uint32_t g_TextHash3 = 0xAAAAAAAA;

bool VerifySectionIntegrity() {
    PVOID base = Resolver::GetModuleBase(0);
    if (!base) return true;
    uint32_t expected;
    if (g_TextHash1 == g_TextHash2) expected = g_TextHash1;
    else if (g_TextHash1 == g_TextHash3) expected = g_TextHash1;
    else if (g_TextHash2 == g_TextHash3) expected = g_TextHash2;
    else return false;
    if (expected == 0xAAAAAAAA) return true;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)base + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (Hashing::HashString((const char*)section[i].Name) == Hashing::HashString(".text")) {
            uint32_t currentHash = Hashing::HashString(std::string_view((char*)base + section[i].VirtualAddress, section[i].Misc.VirtualSize));
            return currentHash == expected;
        }
    }
    return true;
}

bool DetectHooks() {
    PVOID ntdll = Resolver::GetModuleBase(Hashing::HashStringW(L"ntdll.dll"));
    if (!ntdll) return false;
    BYTE* pNtQueryInfo = (BYTE*)Resolver::GetExport(ntdll, Hashing::HashString("NtQueryInformationProcess"));
    return pNtQueryInfo && (*pNtQueryInfo == 0xE9 || *pNtQueryInfo == 0xCC);
}

bool DetectProcessHollowing() {
    PVOID base = Resolver::GetModuleBase(0);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    BYTE* ep = (BYTE*)base + nt->OptionalHeader.AddressOfEntryPoint;
    if (*ep == 0xE9 || *ep == 0xCC) return true;
    return false;
}

bool DetectInjectedThreads() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == GetCurrentProcessId()) {
                // Feature: Check if thread start address is outside of all loaded modules
                // (Requires NtQueryInformationProcess with ThreadQuerySetWin32StartAddress)
                // For now, we return false but the loop structure is ready for full implementation.
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    return false;
}

void ErasePEHeader() {
    PVOID base = Resolver::GetModuleBase(0);
    if (!base) return;
    DWORD old; SIZE_T size = 4096; PVOID addr = base;
    if (Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, PAGE_READWRITE, &old) == 0) {
        memset(base, 0, 4096);
        Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, old, &old);
    }
}

void MangleSizeOfImage() {
    PVOID base = Resolver::GetModuleBase(0);
    if (!base) return;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    DWORD old; SIZE_T size = 4; PVOID addr = &nt->OptionalHeader.SizeOfImage;
    if (Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, PAGE_READWRITE, &old) == 0) {
        nt->OptionalHeader.SizeOfImage += 0x1000;
        Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, old, &old);
    }
}

void PatchAntiAttach() {
    PVOID ntdll = Resolver::GetModuleBase(Hashing::HashStringW(L"ntdll.dll"));
    if (!ntdll) return;
    PVOID pBreakin = Resolver::GetExport(ntdll, Hashing::HashString("DbgUiRemoteBreakin"));
    if (pBreakin) {
        DWORD oldProtect; SIZE_T size = 1; PVOID addr = pBreakin;
        Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, PAGE_READWRITE, &oldProtect);
        *(BYTE*)pBreakin = 0xC3;
        Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, oldProtect, &oldProtect);
    }
}

} // namespace IronLock::Modules::Memory
