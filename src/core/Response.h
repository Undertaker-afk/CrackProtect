#pragma once
#include <windows.h>

namespace IronLock::Core {

enum class ThreatLevel {
    SILENT = 1,
    MISDIRECT = 2,
    DELAYED_CRASH = 3,
    HARD_TERMINATE = 4
};

class Response {
public:
    static void Trigger(ThreatLevel level);
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
