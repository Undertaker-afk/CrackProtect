#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace IronLock::Core {

class Audit {
public:
    static void Log(const std::string& event);
    static void Flush();

private:
    static std::vector<std::string> m_logs;
};

} // namespace IronLock::Core
