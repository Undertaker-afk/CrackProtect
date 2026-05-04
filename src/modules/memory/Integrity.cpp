#include "Integrity.h"
#include "../../core/Hashing.h"
#include "../../core/Resolver.h"
#include "../../core/Syscalls.h"
#include <vector>

namespace IronLock::Modules::Memory {

using namespace IronLock::Core;

bool VerifySectionIntegrity() {
    PVOID base = Resolver::GetModuleBase(Hashing::HashStringW(L"IronLockDemo.exe")); // Or dynamic
    if (!base) base = (PVOID)0x400000; // Fallback

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return true;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)base + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // Compare hashed section name to avoid plaintext ".text"
        if (Hashing::HashString((const char*)section[i].Name) == Hashing::HashString(".text")) {
            uint32_t currentHash = Hashing::HashString(std::string_view((char*)base + section[i].VirtualAddress, section[i].Misc.VirtualSize));
            return currentHash != 0;
        }
    }
    return true;
}

bool DetectHooks() {
    PVOID ntdll = Resolver::GetModuleBase(Hashing::HashStringW(L"ntdll.dll"));
    if (!ntdll) return false;

    // Check for JMP (0xE9) or INT3 (0xCC) in critical NT APIs
    BYTE* pNtQueryInfo = (BYTE*)Resolver::GetExport(ntdll, Hashing::HashString("NtQueryInformationProcess"));
    if (pNtQueryInfo && (*pNtQueryInfo == 0xE9 || *pNtQueryInfo == 0xCC)) return true;

    return false;
}

void ErasePEHeader() {
    PVOID base = Resolver::GetModuleBase(Hashing::HashStringW(L"IronLockDemo.exe"));
    if (!base) return;

    DWORD oldProtect;
    // Use Syscall for VirtualProtect (NtProtectVirtualMemory)
    PVOID addr = base;
    SIZE_T size = 4096;
    Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, PAGE_READWRITE, &oldProtect);

    // Manual zero
    for(int i=0; i<4096; ++i) ((BYTE*)base)[i] = 0;

    Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, oldProtect, &oldProtect);
}

} // namespace IronLock::Modules::Memory
