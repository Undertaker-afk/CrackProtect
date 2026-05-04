#include "Response.h"
#include "Syscalls.h"
#include "Hashing.h"
#include <thread>
#include <chrono>

namespace IronLock::Core {

void Response::Trigger(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::SILENT: SilentCorruption(); break;
        case ThreatLevel::MISDIRECT: Misdirect(); break;
        case ThreatLevel::DELAYED_CRASH: DelayedCrash(); break;
        case ThreatLevel::HARD_TERMINATE: HardTerminate(); break;
    }
}

void Response::SilentCorruption() {
    // Logic bomb: gradually corrupt a critical application flag
}

void Response::Misdirect() {
    // Mislead the analyst by returning fake license/auth results
}

void Response::DelayedCrash() {
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::minutes(5));
        // Trigger a crash that looks like a memory corruption
        volatile int* p = (int*)0xDEADC0DE;
        *p = 0;
    }).detach();
}

void Response::HardTerminate() {
    // Feature 30: System BSOD Response (Needs SeShutdownPrivilege often, but can try NtRaiseHardError)
    // For now, hard terminate via direct syscall
    Syscalls::DoSyscall(Hashing::HashString("NtTerminateProcess"), (HANDLE)-1, 0);
}

void Response::FakeCorruption() {
    // Feature 29: Fake File Corruption Response
    // Display a message box or modify a file to look corrupted
}

void Response::SystemBSOD() {
    // Feature 30: NtRaiseHardError trick
    uint32_t response;
    Syscalls::DoSyscall(Hashing::HashString("NtRaiseHardError"), 0xC0000001, 0, 0, 0, 6, &response);
}

} // namespace IronLock::Core
