#include "Syscalls.h"
#include "Resolver.h"
#include <map>

namespace IronLock::Core {

static std::map<uint32_t, uint32_t> g_SyscallTable;

extern "C" NTSTATUS DirectSyscall(uint32_t num, PVOID a1, PVOID a2, PVOID a3, PVOID a4, PVOID a5, PVOID a6);

bool Syscalls::Initialize() {
    PVOID ntdll = Resolver::GetModuleBase(Hashing::HashStringW(L"ntdll.dll"));
    if (!ntdll) return false;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dosHeader->e_lfanew);
    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ntdll + exportDirRva);

    DWORD* names = (DWORD*)((BYTE*)ntdll + exportDir->AddressOfNames);
    DWORD* functions = (DWORD*)((BYTE*)ntdll + exportDir->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)ntdll + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)ntdll + names[i]);
        if (name[0] == 'N' && name[1] == 't') {
            uint32_t hash = Hashing::HashString(name);
            BYTE* funcAddr = (BYTE*)ntdll + functions[ordinals[i]];

            // Hell's Gate: search for the 'mov eax, SSN' pattern
            if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B && funcAddr[2] == 0xD1 && funcAddr[3] == 0xB8) {
                uint32_t ssn = *(uint32_t*)(funcAddr + 4);
                g_SyscallTable[hash] = ssn;
            } else if (funcAddr[0] == 0xB8) { // Alternative pattern
                 uint32_t ssn = *(uint32_t*)(funcAddr + 1);
                 g_SyscallTable[hash] = ssn;
            }
        }
    }
    return true;
}

uint32_t Syscalls::GetSyscallNumber(uint32_t functionHash) {
    auto it = g_SyscallTable.find(functionHash);
    if (it != g_SyscallTable.end()) return it->second;
    return 0xFFFFFFFF;
}

NTSTATUS Syscalls::InternalSyscall(uint32_t num, ...) {
    va_list args;
    va_start(args, num);

    PVOID a1 = va_arg(args, PVOID);
    PVOID a2 = va_arg(args, PVOID);
    PVOID a3 = va_arg(args, PVOID);
    PVOID a4 = va_arg(args, PVOID);
    PVOID a5 = va_arg(args, PVOID);
    PVOID a6 = va_arg(args, PVOID);

    va_end(args);

    return DirectSyscall(num, a1, a2, a3, a4, a5, a6);
}

} // namespace IronLock::Core
