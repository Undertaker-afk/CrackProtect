#include "Response.h"
#include "Syscalls.h"
#include "Hashing.h"
#include <thread>
#include <chrono>
#include <windows.h>

namespace IronLock::Core {

static volatile uint64_t g_DecoyGlobalState = 0x1234567887654321;

void Response::Trigger(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::SILENT: SilentCorruption(); break;
        case ThreatLevel::MISDIRECT: Misdirect(); break;
        case ThreatLevel::DELAYED_CRASH: DelayedCrash(); break;
        case ThreatLevel::HARD_TERMINATE: HardTerminate(); break;
    }
}

void Response::SilentCorruption() {
    // Logic Bomb: Corrupt internal state without immediate failure
    g_DecoyGlobalState ^= (1ULL << (__rdtsc() % 64));
}

void Response::Misdirect() {
    // Return fake valid results (implementation dependent on caller context)
}

void Response::DelayedCrash() {
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::minutes(5));
        RaiseException(0xDEADC0DE, 0, 0, NULL);
    }).detach();
}

void Response::HardTerminate() {
    Syscalls::DoSyscall(Hashing::HashString("NtTerminateProcess"), (HANDLE)-1, (NTSTATUS)0xC0000420);
}

void Response::FakeCorruption() {
    MessageBoxA(NULL, "The application has encountered an unrecoverable disk error.", "IronLock Protection", MB_OK | MB_ICONERROR);
}

void Response::SystemBSOD() {
    uint32_t resp;
    Syscalls::DoSyscall(Hashing::HashString("NtRaiseHardError"), 0xC000021A, 0, 0, 0, 6, &resp);
}

} // namespace IronLock::Core
