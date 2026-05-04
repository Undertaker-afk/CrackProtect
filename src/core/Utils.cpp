#include "Utils.h"
#include "Resolver.h"
#include <tlhelp32.h>
#include <random>

namespace IronLock::Core::Utils {

bool IsProcessRunning(const std::wstring& name) {
    bool found = false;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (name == entry.szExeFile) {
                    found = true;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    return found;
}

uint64_t GetTickCount64_Direct() {
    return GetTickCount64();
}

void RandomDelay(uint32_t minMs, uint32_t maxMs) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(minMs, maxMs);
    Sleep(dis(gen));
}

} // namespace IronLock::Core::Utils
