#include "Audit.h"
#include "Crypto.h"
#include "Syscalls.h"
#include "Hashing.h"

namespace IronLock::Core {

std::vector<std::string> Audit::m_logs;

void Audit::Log(const std::string& event) {
    m_logs.push_back(event);
}

void Audit::Flush() {
    // Encrypt and save logs to a file or send to telemetry
    // For now, we clear the list to simulate flush
    m_logs.clear();
}

} // namespace IronLock::Core
