#include "Integrity.h"
#include "../../core/Syscalls.h"
#include "../../core/Hashing.h"
#include "../../core/Resolver.h"

namespace IronLock::Modules::Memory {

using namespace IronLock::Core;

void ErasePEHeader() {
    PVOID base = Resolver::GetModuleBase(0);
    if (!base) return;

    DWORD old;
    SIZE_T size = 4096;
    PVOID addr = base;

    // NtProtectVirtualMemory
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

    DWORD old;
    SIZE_T size = 4;
    PVOID addr = &nt->OptionalHeader.SizeOfImage;

    if (Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, PAGE_READWRITE, &old) == 0) {
        nt->OptionalHeader.SizeOfImage += 0x1000;
        Syscalls::DoSyscall(Hashing::HashString("NtProtectVirtualMemory"), (HANDLE)-1, &addr, &size, old, &old);
    }
}

} // namespace IronLock::Modules::Memory
