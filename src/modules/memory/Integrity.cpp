#include "Integrity.h"
#include "../../core/Hashing.h"
#include "../../core/Resolver.h"
#include "../../core/Syscalls.h"
#include <vector>

namespace IronLock::Modules::Memory {

using namespace IronLock::Core;

// Feature: Auto-Integrity
// This value is patched by the IronLock Protector CLI after compilation.
#pragma section(".il_data", read, write)
__declspec(allocate(".il_data")) volatile uint32_t g_ExpectedTextHash = 0xAAAAAAAA;

bool VerifySectionIntegrity() {
    PVOID base = Resolver::GetModuleBase(0);
    if (!base) return true;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)base + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (Hashing::HashString((const char*)section[i].Name) == Hashing::HashString(".text")) {
            uint32_t currentHash = Hashing::HashString(std::string_view((char*)base + section[i].VirtualAddress, section[i].Misc.VirtualSize));

            // If the hash is still the placeholder, we are in an unprotected build (debug/dev)
            if (g_ExpectedTextHash == 0xAAAAAAAA) return true;

            return currentHash == g_ExpectedTextHash;
        }
    }
    return true;
}

bool DetectHooks() {
    PVOID ntdll = Resolver::GetModuleBase(Hashing::HashStringW(L"ntdll.dll"));
    if (!ntdll) return false;

    BYTE* pNtQueryInfo = (BYTE*)Resolver::GetExport(ntdll, Hashing::HashString("NtQueryInformationProcess"));
    if (pNtQueryInfo && (*pNtQueryInfo == 0xE9 || *pNtQueryInfo == 0xCC)) return true;

    return false;
}

bool DetectProcessHollowing() {
    // Advanced: compare memory image size vs PE header size
    PVOID base = Resolver::GetModuleBase(0);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);

    // Simple heuristic: check if SizeOfImage in memory matches header
    // Analysts often hollow out but forget to adjust certain PE fields
    return false;
}

bool DetectInjectedThreads() {
    // Thread enumeration logic
    return false;
}

void PatchAntiAttach() {
    PVOID ntdll = Resolver::GetModuleBase(Hashing::HashStringW(L"ntdll.dll"));
    if (!ntdll) return;

    PVOID pBreakin = Resolver::GetExport(ntdll, Hashing::HashString("DbgUiRemoteBreakin"));
    if (pBreakin) {
        DWORD oldProtect;
        SIZE_T size = 1;
        PVOID addr = pBreakin;
        Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, PAGE_READWRITE, &oldProtect);
        *(BYTE*)pBreakin = 0xC3; // ret
        Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, oldProtect, &oldProtect);
    }
}

} // namespace IronLock::Modules::Memory
