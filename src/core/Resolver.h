#pragma once
#include <windows.h>
#include <winternl.h>
#include "Hashing.h"

namespace IronLock::Core {

class Resolver {
public:
    static PVOID GetModuleBase(uint32_t moduleHash);
    static PVOID GetExport(PVOID moduleBase, uint32_t exportHash);

    template<typename T>
    static T GetExport(uint32_t moduleHash, uint32_t exportHash) {
        PVOID base = GetModuleBase(moduleHash);
        if (!base) return nullptr;
        return reinterpret_cast<T>(GetExport(base, exportHash));
    }
};

} // namespace IronLock::Core
