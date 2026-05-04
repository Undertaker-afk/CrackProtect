#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace IronLock::Core {

struct AuditEvent {
    std::string category;
    std::string message;
    std::string details;
    uint64_t timestamp;
};

class Audit {
public:
    static void Log(const std::string& event);
    static void LogEvent(const AuditEvent& event);
    static std::vector<AuditEvent> GetEvents();
    static void Flush();

private:
    static std::vector<std::string> m_logs;
    static std::vector<AuditEvent> m_events;
};

} // namespace IronLock::Core
