#include "Resolver.h"
#include <string>
#include <intrin.h>

namespace IronLock::Core {

typedef struct _LDR_DATA_TABLE_ENTRY_INTERNAL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_INTERNAL, *PLDR_DATA_TABLE_ENTRY_INTERNAL;

PVOID Resolver::GetModuleBase(uint32_t moduleHash) {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif

    if (moduleHash == 0) return peb->ImageBaseAddress;

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY_INTERNAL entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_INTERNAL, InMemoryOrderLinks);

        if (entry->BaseDllName.Buffer) {
            uint32_t hash = Hashing::HashStringW(std::wstring_view(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t)));
            if (hash == moduleHash) return entry->DllBase;
        }
        current = current->Flink;
    }
    return nullptr;
}

PVOID Resolver::GetExport(PVOID moduleBase, uint32_t exportHash) {
    if (!moduleBase) return nullptr;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRva == 0) return nullptr;

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)moduleBase + exportDirRva);
    DWORD* names = (DWORD*)((BYTE*)moduleBase + exportDir->AddressOfNames);
    DWORD* functions = (DWORD*)((BYTE*)moduleBase + exportDir->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)moduleBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)moduleBase + names[i]);
        if (Hashing::HashString(name) == exportHash) {
            return (BYTE*)moduleBase + functions[ordinals[i]];
        }
    }

    // Support for resolving by ordinal if hash is within a certain range or specially marked
    // (Ordinal resolution logic would go here)

    return nullptr;
}

} // namespace IronLock::Core
