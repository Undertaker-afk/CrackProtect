# IronLock Protection Techniques

## Module 1 & 2: Anti-Debugging
- **PEB!BeingDebugged**: Standard user-mode check.
- **NtQueryInformationProcess**:
  - `ProcessDebugPort` (0x7): Detects if a debugger is attached.
  - `ProcessDebugFlags` (0x1F): Detects if debugging is enabled.
- **Invalid Handle**: Calls `CloseHandle` with a junk handle to trigger `EXCEPTION_INVALID_HANDLE` under a debugger.
- **Timing Delta**: Uses `RDTSC` to measure execution time across instructions, detecting single-stepping.
- **Hardware Breakpoints**: Inspects `Dr0-Dr7` registers via `GetThreadContext`.
- **KUSER_SHARED_DATA**: Directly checks `KdDebuggerEnabled` in kernel-shared memory.

## Module 3 & 4: Anti-VM & Sandbox
- **CPUID**:
  - Hypervisor bit (ECX bit 31).
  - Hypervisor vendor string (leaf 0x40000000).
- **VM Backdoor**: VMware-specific I/O port `0x5658` ('VMXh').
- **Driver Presence**: Scans for `VBoxGuest.sys`, `vmhgfs.sys`, etc.
- **Sandbox Heuristics**:
  - Uptime check (minimum 10 minutes).
  - Disk size (minimum 60 GB).
  - Sleep acceleration detection.

## Module 5, 11, 12, 13: Tool & Network Detection
- **Process & Window Scanning**: Detects `x64dbg`, `IDA`, `Wireshark`, etc.
- **Proxy Hijacking**: Inspects registry for local proxies (127.0.0.1).
- **VPN Detection**: Enumerates network adapters for `TAP`, `Wintun`, `VPN`.
- **MITM Certs**: Scans `ROOT` certificate store for `Fiddler`, `Charles`, `PortSwigger`.

## Module 6 & 7: Memory & Anti-Disassembly
- **PE Header Erasure**: Wipes MZ/PE signature from memory at runtime.
- **Hook Detection**: Scans prologues of critical APIs for `JMP` or `INT3`.
- **Opaque Predicates**: Branch logic that always resolves the same way but confuses linear disassemblers.
- **Junk Code**: Inserts non-executed bytes that mimic valid instructions.

## Module 8: Code Virtualization
- **Stack VM**: Custom bytecode interpreter for sensitive logic.
- **Header Macros**: Allows "compiling" C++ logic into VM bytecode at compile-time.

## Module 10: Stealth
- **Dynamic Resolver**: PEB walking to find exports without `GetProcAddress`.
- **Hell's Gate**: Dynamic syscall discovery by parsing `ntdll.dll` to find SSNs.
- **Direct Syscalls**: Bypasses user-mode hooks by executing `syscall` instruction directly.
