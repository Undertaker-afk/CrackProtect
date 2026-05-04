#pragma once
#include <windows.h>
#include <cstdint>

#ifdef IRONLOCK_EXPORTS
#define IRONLOCK_API __declspec(dllexport)
#else
#define IRONLOCK_API
#endif

namespace IronLock {

// Public API for IronLock SDK

// Initialize the SDK (resolves syscalls, etc.)
IRONLOCK_API bool ProtectionInit();

// Aggregate check for environment safety
IRONLOCK_API bool IsEnvironmentSafe();

// Individual Module Checks
namespace AntiDebug {
    IRONLOCK_API bool IsDebuggerPresent();
    IRONLOCK_API bool CheckKernelDebugger();
}

namespace AntiVM {
    IRONLOCK_API bool IsRunningInVM();
}

namespace Sandbox {
    IRONLOCK_API bool IsRunningInSandbox();
}

namespace Network {
    IRONLOCK_API bool IsNetworkSafe();
    IRONLOCK_API bool IsVpnActive();
}

// Memory & Integrity
namespace Integrity {
    IRONLOCK_API bool CheckSelfIntegrity();
}

// Register a callback for when a threat is detected
typedef void (*TripwireCallback)(int reason);
IRONLOCK_API void RegisterTripwire(TripwireCallback callback);

} // namespace IronLock
