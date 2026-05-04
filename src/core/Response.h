#pragma once
#include <windows.h>

#include <cstdint>
#include <string>

namespace IronLock::Core {

enum class ThreatLevel {
    SILENT = 1,
    MISDIRECT = 2,
    DELAYED_CRASH = 3,
    HARD_TERMINATE = 4
};

enum class ResponseTriggerType {
    IMMEDIATE = 0,
    TIME_DELAY,
    USAGE_MILESTONE,
    API_PATH
};

struct TriggerCondition {
    ResponseTriggerType type{ResponseTriggerType::IMMEDIATE};
    uint32_t delayMs{0};
    uint32_t usageMilestone{0};
    std::string apiPath;
};

struct ResponseDecision {
    ThreatLevel level{ThreatLevel::SILENT};
    TriggerCondition trigger{};
    bool deferred{false};
};

class Response {
public:
    static void ConfigureDeterministicMode(bool deterministic);
    static ResponseDecision SelectForThreat(const std::string& threatKey, ThreatLevel suggestedLevel);
    static void Trigger(ThreatLevel level);
    static void Trigger(const ResponseDecision& decision);
    static void TickUsage(uint32_t amount = 1);
    static void NotifyApiPath(const std::string& apiPath);
    static bool IsMisdirected();

    // Specific Response Actions
    static void SilentCorruption();
    static void Misdirect();
    static void DelayedCrash();
    static void HardTerminate();
    static void FakeCorruption();
    static void SystemBSOD();
};

} // namespace IronLock::Core
