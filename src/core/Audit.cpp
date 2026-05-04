#include "Audit.h"
#include "Crypto.h"
#include "Syscalls.h"
#include "Hashing.h"
#include <ctime>
#include <sstream>

namespace IronLock::Core {

std::vector<std::string> Audit::m_logs;
std::vector<AuditEvent> Audit::m_events;

void Audit::Log(const std::string& event) {
    std::time_t now = std::time(nullptr);
    std::string t = std::ctime(&now);
    t.pop_back(); // remove newline
    m_logs.push_back("[" + t + "] " + event);
}

void Audit::LogEvent(const AuditEvent& event) {
    m_events.push_back(event);
}

std::vector<AuditEvent> Audit::GetEvents() {
    return m_events;
}

void Audit::Flush() {
    if (m_logs.empty()) return;

    // Encrypt logs with per-build key
    uint8_t key[32] = { 0 }; // Should be randomized
    uint8_t iv[16] = { 0 };

    std::stringstream ss;
    for (const auto& log : m_logs) ss << log << "\n";
    std::string fullLog = ss.str();

    std::vector<uint8_t> encrypted(fullLog.size());
    Crypto::AES256_Encrypt(key, iv, (uint8_t*)fullLog.data(), fullLog.size(), encrypted.data());

    // Write to hidden file or send to telemetry
    // ...
    m_logs.clear();
    m_events.clear();
}

} // namespace IronLock::Core
