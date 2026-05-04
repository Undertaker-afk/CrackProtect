#include "AntiAnalysis.h"

#include "../../core/Audit.h"
#include "../../core/Hashing.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <intrin.h>
#include <psapi.h>
#include <string>
#include <tlhelp32.h>
#include <windows.h>

namespace IronLock::Modules::AntiAnalysis {
namespace {

bool g_telemetryMode = false;

void Telemetry(const Signal& s) {
    if (!g_telemetryMode) return;
    Core::Audit::LogEvent({"telemetry.antianalysis", s.check, s.reason, static_cast<uint64_t>(std::time(nullptr))});
}

bool ContainsInsensitive(const std::wstring& text, const std::wstring& pattern) {
    std::wstring a = text;
    std::wstring b = pattern;
    std::transform(a.begin(), a.end(), a.begin(), ::towlower);
    std::transform(b.begin(), b.end(), b.begin(), ::towlower);
    return a.find(b) != std::wstring::npos;
}

Signal CheckInjectedModules() {
    constexpr std::array<const wchar_t*, 8> kSuspicious = {
        L"frida", L"gadget", L"dynamorio", L"pinvm", L"pincrt", L"qemu", L"bochs", L"dbghelp_hook"
    };

    HMODULE modules[1024]{};
    DWORD needed = 0;
    bool suspicious = false;
    std::string reason = "No suspicious injected modules";

    if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        const size_t count = needed / sizeof(HMODULE);
        wchar_t path[MAX_PATH];
        for (size_t i = 0; i < count; ++i) {
            if (!GetModuleFileNameExW(GetCurrentProcess(), modules[i], path, MAX_PATH)) continue;
            const std::wstring wpath(path);
            for (auto* token : kSuspicious) {
                if (ContainsInsensitive(wpath, token)) {
                    suspicious = true;
                    reason = "Suspicious module token present in process module list";
                    break;
                }
            }
            if (suspicious) break;
        }
    }

    return {"antianalysis.instrumentation.modules", suspicious, 0.90, 0.92, reason};
}

Signal CheckNtDllStubIntegrity() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    FARPROC ntProtect = ntdll ? GetProcAddress(ntdll, "NtProtectVirtualMemory") : nullptr;
    bool suspicious = false;
    std::string reason = "NTDLL syscall stubs look consistent";

    if (!ntdll || !ntProtect) {
        suspicious = true;
        reason = "Failed to resolve NTDLL exports";
    } else {
        const auto* p = reinterpret_cast<const unsigned char*>(ntProtect);
        if (p[0] == 0xE9 || p[0] == 0xE8 || p[0] == 0xCC || p[0] == 0x90) {
            suspicious = true;
            reason = "Potential trampoline/hook observed in NTDLL syscall stub";
        }
    }

    return {"antianalysis.hooks.ntdll_stub", suspicious, 0.95, 0.90, reason};
}

Signal CheckHardwareBreakpoints() {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    bool suspicious = false;
    std::string reason = "No active hardware breakpoints";

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        suspicious = (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr7);
        if (suspicious) reason = "Hardware debug register state is non-zero";
    }

    return {"antianalysis.breakpoints.hw_registers", suspicious, 0.88, 0.85, reason};
}

Signal CheckCpuidAndTimerSkew() {
    int cpuInfo[4]{};
    __cpuid(cpuInfo, 1);
    const bool hypervisorBit = (cpuInfo[2] & (1 << 31)) != 0;

    auto start = std::chrono::high_resolution_clock::now();
    Sleep(25);
    auto end = std::chrono::high_resolution_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    const bool timerSkew = elapsed < 15 || elapsed > 150;

    bool suspicious = hypervisorBit && timerSkew;
    std::string reason = suspicious ? "CPUID hypervisor bit + timer skew indicates emulation/sandboxing" : "No strong CPUID/timer skew inconsistencies";
    return {"antianalysis.emulator.cpuid_timer", suspicious, 0.70, 0.72, reason};
}

Signal CheckIatEatRedirects() {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC sleepProc = kernel32 ? GetProcAddress(kernel32, "Sleep") : nullptr;
    MEMORY_BASIC_INFORMATION mbi{};
    bool suspicious = false;
    std::string reason = "No obvious IAT/EAT redirection artifacts";

    if (!sleepProc || !VirtualQuery(reinterpret_cast<LPCVOID>(sleepProc), &mbi, sizeof(mbi))) {
        suspicious = true;
        reason = "Unable to validate exported function memory region";
    } else if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
        suspicious = true;
        reason = "Export target points to suspicious memory protection";
    }

    return {"antianalysis.hooks.iat_eat", suspicious, 0.75, 0.70, reason};
}

} // namespace

void ConfigureTelemetry(bool enabled) {
    g_telemetryMode = enabled;
}

Result RunAllChecks() {
    std::vector<Signal> signals;
    signals.push_back(CheckInjectedModules());
    signals.push_back(CheckNtDllStubIntegrity());
    signals.push_back(CheckHardwareBreakpoints());
    signals.push_back(CheckCpuidAndTimerSkew());
    signals.push_back(CheckIatEatRedirects());

    double weightedRisk = 0.0;
    double weight = 0.0;
    for (const auto& s : signals) {
        Telemetry(s);
        weightedRisk += (s.suspicious ? s.score : 0.0) * s.confidence;
        weight += s.confidence;
    }

    const double aggregate = weight > 0.0 ? (weightedRisk / weight) : 0.0;
    return {aggregate >= 0.55, aggregate, signals};
}

} // namespace IronLock::Modules::AntiAnalysis
