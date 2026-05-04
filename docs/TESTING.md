# Testing IronLock

Since IronLock is a Windows-targeted SDK, testing must be performed on a Windows 10/11 system.

## 1. Unit Tests
Individual module tests are located in the `tests/` directory.
Build using CMake:
```bash
mkdir build
cd build
cmake .. -A x64
cmake --build . --config Release
```

## 2. Validation Environments
- **Physical Machine**: All checks should return `FALSE` (safe).
- **VirtualBox/VMware**: `IsRunningInVM()` should return `TRUE`.
- **x64dbg**: `IsDebuggerPresent()` should return `TRUE`.
- **Fiddler/Charles**: `IsNetworkSafe()` should return `FALSE`.
- **Sandboxie/Any.run**: `IsRunningInSandbox()` should return `TRUE`.

## 3. Verifying Stealth
- Open the compiled binary in **IDA Pro**.
- Search for strings like "ntdll.dll" or "IsDebuggerPresent". They should be absent or hashed.
- Verify that critical API calls are replaced with `syscall` instructions.
