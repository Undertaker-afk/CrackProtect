#include "ToolDetect.h"
#include "../../core/Utils.h"
#include "../../core/Hashing.h"
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>

namespace IronLock::Modules::Tools {

// FNV-1a hashes of sensitive process names to avoid plaintext strings
constexpr uint32_t H_X64DBG = IronLock::Core::Hashing::HashString("x64dbg.exe");
constexpr uint32_t H_IDA = IronLock::Core::Hashing::HashString("ida64.exe");

bool CheckProcessNames() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            uint32_t hash = IronLock::Core::Hashing::HashStringW(entry.szExeFile);
            if (hash == H_X64DBG || hash == H_IDA) {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return false;
}

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    wchar_t title[256];
    if (GetWindowTextW(hwnd, title, 256)) {
        std::wstring s(title);
        std::transform(s.begin(), s.end(), s.begin(), ::towupper);
        if (s.find(L"X64DBG") != std::wstring::npos || s.find(L"IDA PRO") != std::wstring::npos) {
            *(bool*)lParam = true;
            return FALSE;
        }
    }
    return TRUE;
}

bool CheckWindowTitles() {
    bool found = false;
    EnumWindows(EnumWindowsProc, (LPARAM)&found);
    return found;
}

bool RunAllToolChecks() {
    return CheckProcessNames() || CheckWindowTitles();
}

} // namespace IronLock::Modules::Tools
