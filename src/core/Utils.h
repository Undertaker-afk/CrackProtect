#pragma once
#include <windows.h>
#include <string>

namespace IronLock::Core::Utils {

std::wstring GetProcessName(DWORD pid);
bool IsProcessRunning(const std::wstring& name);
uint64_t GetTickCount64_Direct();
void RandomDelay(uint32_t minMs, uint32_t maxMs);

} // namespace IronLock::Core::Utils
