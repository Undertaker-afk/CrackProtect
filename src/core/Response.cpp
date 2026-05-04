#include "Response.h"
#include "Syscalls.h"
#include "Hashing.h"
#include <thread>
#include <chrono>
#include <windows.h>

namespace IronLock::Core {

// Decoy global state for silent corruption
static volatile uint64_t g_InternalState = 0xFFFFFFFFFFFFFFFF;

void Response::Trigger(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::SILENT: SilentCorruption(); break;
        case ThreatLevel::MISDIRECT: Misdirect(); break;
        case ThreatLevel::DELAYED_CRASH: DelayedCrash(); break;
        case ThreatLevel::HARD_TERMINATE: HardTerminate(); break;
    }
}

void Response::SilentCorruption() {
    // Gradually flip bits in a decoy state to cause subtle, delayed logic failures
    g_InternalState ^= (1ULL << (std::time(nullptr) % 64));
}

void Response::Misdirect() {
    // In a real app, this would set a "LicenseValid" flag to true while
    // simultaneously disabling critical functionality in a hidden way.
}

void Response::DelayedCrash() {
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::minutes(5));
        volatile int* p = (int*)0xDEADC0DE;
        *p = 0;
    }).detach();
}

void Response::HardTerminate() {
    Syscalls::DoSyscall(Hashing::HashString("NtTerminateProcess"), (HANDLE)-1, 0);
}

void Response::FakeCorruption() {
    // Feature 29: Fake File Corruption Response
    MessageBoxA(NULL, "Critical error: File system corruption detected. Please restart your system.", "System Error", MB_OK | MB_ICONERROR);
}

void Response::SystemBSOD() {
    // Feature 30: System BSOD Response via NtRaiseHardError
    uint32_t response;
    Syscalls::DoSyscall(Hashing::HashString("NtRaiseHardError"), 0xC0000001, 0, 0, 0, 6, &response);
}

} // namespace IronLock::Core
