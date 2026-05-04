#pragma once
#include <windows.h>
#include <winternl.h>
#include "Hashing.h"

namespace IronLock::Core {

class Syscalls {
public:
    static bool Initialize();
    static uint32_t GetSyscallNumber(uint32_t functionHash);

    // Call a syscall by hash
    template<typename... Args>
    static NTSTATUS DoSyscall(uint32_t functionHash, Args... args) {
        uint32_t num = GetSyscallNumber(functionHash);
        if (num == 0xFFFFFFFF) return STATUS_NOT_FOUND;
        return InternalSyscall(num, args...);
    }

private:
    // Internal assembly wrapper or dynamic execution stub
    static NTSTATUS InternalSyscall(uint32_t num, ...);
};

} // namespace IronLock::Core
