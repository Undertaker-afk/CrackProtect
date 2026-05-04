#include "Response.h"
#include "Syscalls.h"
#include "Hashing.h"
#include <thread>
#include <chrono>
#include <windows.h>
#include <atomic>
#include <unordered_map>
#include <mutex>

namespace IronLock::Core {

static volatile uint64_t g_DecoyGlobalState = 0x1234567887654321;
static std::atomic<bool> g_MisdirectMode{ false };
static std::atomic<bool> g_DeterministicMode{ false };
static std::atomic<uint32_t> g_UsageCounter{ 0 };

struct ThreatRuntimeState {
    uint32_t cooldown{0};
    uint32_t hits{0};
};

static std::unordered_map<std::string, ThreatRuntimeState> g_ThreatState;
static std::mutex g_StateMutex;

static uint32_t NextVariant(uint32_t seed) {
    return g_DeterministicMode.load() ? seed : static_cast<uint32_t>(__rdtsc());
}

void Response::ConfigureDeterministicMode(bool deterministic) {
    g_DeterministicMode.store(deterministic);
}

ResponseDecision Response::SelectForThreat(const std::string& threatKey, ThreatLevel suggestedLevel) {
    std::lock_guard<std::mutex> lock(g_StateMutex);
    ThreatRuntimeState& state = g_ThreatState[threatKey];

    if (state.cooldown > 0) {
        --state.cooldown;
        return ResponseDecision{ThreatLevel::SILENT, TriggerCondition{ResponseTriggerType::IMMEDIATE}, true};
    }

    state.hits++;
    const uint32_t variant = NextVariant(state.hits + static_cast<uint32_t>(threatKey.size()));

    TriggerCondition trigger{ResponseTriggerType::IMMEDIATE};
    ThreatLevel selected = suggestedLevel;

    switch (suggestedLevel) {
        case ThreatLevel::SILENT:
            trigger.type = ResponseTriggerType::USAGE_MILESTONE;
            trigger.usageMilestone = g_UsageCounter.load() + 5 + (variant % 5);
            break;
        case ThreatLevel::MISDIRECT:
            trigger.type = ResponseTriggerType::API_PATH;
            trigger.apiPath = (variant % 2 == 0) ? "license/verify" : "session/refresh";
            break;
        case ThreatLevel::DELAYED_CRASH:
            trigger.type = ResponseTriggerType::TIME_DELAY;
            trigger.delayMs = 30000 + ((variant % 5) * 10000);
            break;
        case ThreatLevel::HARD_TERMINATE:
            trigger.type = ResponseTriggerType::IMMEDIATE;
            break;
    }

    if (state.hits > 1 && suggestedLevel == ThreatLevel::HARD_TERMINATE && (variant % 3 != 0)) {
        selected = ThreatLevel::DELAYED_CRASH;
        trigger.type = ResponseTriggerType::TIME_DELAY;
        trigger.delayMs = 45000;
    }

    state.cooldown = 2 + (variant % 3);
    return ResponseDecision{selected, trigger, false};
}

void Response::Trigger(const ResponseDecision& decision) {
    switch (decision.trigger.type) {
        case ResponseTriggerType::IMMEDIATE:
            Trigger(decision.level);
            return;
        case ResponseTriggerType::TIME_DELAY:
            std::thread([decision]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(decision.trigger.delayMs));
                Trigger(decision.level);
            }).detach();
            return;
        case ResponseTriggerType::USAGE_MILESTONE:
            if (g_UsageCounter.load() >= decision.trigger.usageMilestone) {
                Trigger(decision.level);
            }
            return;
        case ResponseTriggerType::API_PATH:
            return;
    }
}

void Response::TickUsage(uint32_t amount) {
    g_UsageCounter.fetch_add(amount);
}

void Response::NotifyApiPath(const std::string& apiPath) {
    if (g_MisdirectMode.load() && (apiPath == "license/verify" || apiPath == "session/refresh")) {
        SilentCorruption();
    }
}

void Response::Trigger(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::SILENT: SilentCorruption(); break;
        case ThreatLevel::MISDIRECT: Misdirect(); break;
        case ThreatLevel::DELAYED_CRASH: DelayedCrash(); break;
        case ThreatLevel::HARD_TERMINATE: HardTerminate(); break;
    }
}

void Response::SilentCorruption() {
    g_DecoyGlobalState ^= (1ULL << (__rdtsc() % 64));
}

void Response::Misdirect() {
    g_MisdirectMode.store(true);
}

bool Response::IsMisdirected() {
    return g_MisdirectMode.load();
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
