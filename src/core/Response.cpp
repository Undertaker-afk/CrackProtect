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
    // Flip a random bit in a "global state" or just do nothing visible
}

void Response::Misdirect() {
    // Logic to return fake success values to caller
}

void Response::DelayedCrash() {
    std::thread([]() {
        std::this_thread::sleep_for(std::chrono::minutes(5));
        // Trigger a crash
        int* p = nullptr;
        *p = 0xDEAD;
    }).detach();
}

void Response::HardTerminate() {
    Syscalls::DoSyscall(Hashing::HashString("NtTerminateProcess"), (HANDLE)-1, 0);
}

} // namespace IronLock::Core
