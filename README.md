# IronLock Protection SDK

IronLock is a comprehensive, production-grade anti-crack and anti-debugging protection library for Windows x86/x64. It is designed to be modular, stealthy, and resilient against modern analysis tools.

## 🚀 Key Features

- **Direct Syscalls**: Uses Hell's Gate and Halo's Gate to dynamically resolve and execute system calls, bypassing user-mode hooks.
- **Manual API Resolution**: Walks the PEB to find module bases and exports without using standard Win32 imports.
- **Advanced Anti-X**:
  - User-mode and Kernel-mode debugger detection.
  - Virtual machine and Sandbox environment detection (VMware, VBox, Hyper-V, etc.).
  - Analysis tool scanning (x64dbg, IDA Pro, Wireshark, etc.).
- **Memory Integrity**:
  - Triple-redundant section hashing with majority-voting consensus.
  - PE header erasure and anti-dumping techniques.
- **Custom Code Virtualization**: Stack-based bytecode VM with an integrated transpiler.
- **Honeypotting**: 20+ bait functions designed to trap and mislead analysts.
- **Stealth**: XOR/AES encrypted strings and function name randomization.

## 🛠️ Tooling Suite

- [IronLock Compiler Engine](./compiler/main.cpp): A full MSVC cl.exe wrapper for automated protection.
- [IronLock CLI](./examples/ilprotect_cli.cpp): Command-line interface for binary hardening.
- [IronLock GUI](./examples/ilgui.cpp): Win32-based interface with feature selection and drag-and-drop.
- [IronLock Transpiler](./examples/iltranspiler.cpp): Source-to-bytecode virtualization tool.

## 📚 Documentation

- [Detailed Techniques](./docs/TECHNIQUES.md)
- [Bypass Analysis & Countermeasures](./docs/BYPASS_ANALYSIS.md)
- [Testing Guide](./docs/TESTING.md)
- [Ethical Disclaimer](./docs/ETHICAL_DISCLAIMER.md)
- [Development Roadmap & TODO](./TODO.md)

---

## PROJECT SPECIFICATIONS (ORIGINAL REQUIREMENTS)

### MODULE 1 — ANTI-DEBUGGING (USER MODE)
Implement ALL of the following debugger detection methods:
1. IsDebuggerPresent() API check (PEB.BeingDebugged flag)
2. CheckRemoteDebuggerPresent() via NtQueryInformationProcess()
3. ProcessDebugPort check (NtQueryInformationProcess with ProcessDebugPort = 0x7)
4. ProcessDebugObjectHandle check
5. ProcessDebugFlags check (NtQueryInformationProcess ProcessDebugFlags = 0x1F)
6. CloseHandle() with invalid handle → detect EXCEPTION_INVALID_HANDLE (0xC0000008)
7. NtClose() with invalid handle (direct syscall variant)
8. Heap flags inspection (PEB.NtGlobalFlag, heap ForceFlags)
9. INT 3 / 0xCC software breakpoint scanning in own code regions
10. Hardware breakpoint detection via CONTEXT.Dr0–Dr3 debug registers
11. RDTSC-based timing delta analysis (detect slowdown from single-step / breakpoint traps)
12. GetTickCount / QueryPerformanceCounter timing cross-check
13. OutputDebugString() trick (error code behavior differs under debugger)
14. Guard page exception trick using VirtualProtect() + GUARD_PAGE flag
15. TLS (Thread Local Storage) callback abuse for early pre-EntryPoint detection
16. UnhandledExceptionFilter() presence check
17. Trap Flag (TF) single-step exception trick
18. Parent process name validation (legitimate parent = explorer.exe, not a debugger)
19. SeDebugPrivilege check (debuggers often have this privilege)
20. NtSetInformationThread with ThreadHideFromDebugger (and detect if this is already applied by an attacker)
21. DbgBreakPoint / DbgUiRemoteBreakin hook integrity check
22. Heap handle count comparison (debugger inflates handle count)
23. "Heaven's Gate" 32-to-64-bit segment switch detection

### MODULE 2 — ANTI-DEBUGGING (KERNEL MODE / DRIVER-LEVEL CHECKS)
1. KdDebuggerEnabled / KdDebuggerNotPresent flags (via NtQuerySystemInformation or shared kernel data)
2. Check SharedUserData!KdDebuggerEnabled
3. Detect kernel debugger via KUSER_SHARED_DATA
4. NtQuerySystemInformation(SystemKernelDebuggerInformation)
5. Detect WinDbg kernel sessions via driver heartbeat absence
6. Check for presence of known kernel debug drivers (e.g., dbgeng.dll, kd.exe artifacts)

### MODULE 3 — VIRTUAL MACHINE DETECTION
Implement detection for ALL of the following hypervisors/emulators, matching al-khaser's full coverage:
A. GENERIC VM DETECTION:
   - CPUID hypervisor bit (ECX bit 31 of leaf 1)
   - CPUID hypervisor vendor string (leaf 0x40000000)
   - SMBIOS/DMI string inspection
   - Raw SMBIOS via WMI (Win32_BIOS, Win32_ComputerSystem)
   - Power state enumeration (most VMs don't support S1–S4 power states)
   - Disk geometry inspection (VM disk sizes are often unrealistically round)
   - Total physical disk space heuristic (sandbox drives are often small)
   - Lack of battery / thermal sensors (most VMs have no power management)
   - MAC address OUI check against known VM vendors
   - Screen resolution heuristic (VMs often use standard low-res)
   - Loaded driver/module list inspection (vmmouse.sys, vmhgfs.sys, vboxguest.sys, etc.)
   - Registry key artifact scanning (HKLM\SOFTWARE\VMware Inc., VirtualBox, etc.)
   - Known VM process name scanning (vmtoolsd.exe, vboxservice.exe, etc.)
   - Genuine Windows installation check (NtQueryLicenseValue with Kernel-VMDetection-Private)

B. VIRTUALBOX DETECTION:
   - VBox guest additions registry keys
   - VBoxGuest, VBoxMouse, VBoxSF driver presence
   - VBoxRev / VBoxVer SMBIOS OEM fields
   - VirtualBox-specific CPUID leaves
   - Trap Flag bug in older VirtualBox versions (EIP discrepancy)

C. VMWARE DETECTION:
   - VMware backdoor I/O port (port 0x5658 "VMXh" magic)
   - VMware CPUID signature
   - vmtoolsd.exe / vmwaretray.exe process names
   - VMware-specific registry keys
   - VMware network adapter MAC OUI (00:0C:29, 00:50:56)

D. HYPER-V DETECTION:
   - Hyper-V CPUID signature ("Microsoft Hv")
   - Hyper-V specific MSR reads
   - vmbus driver presence

E. QEMU / KVM DETECTION:
   - QEMU CPUID signature ("KVMKVMKVM")
   - QEMU virtual hardware artifacts
   - Known QEMU process / file names

F. XEN DETECTION:
   - Xen CPUID leaf (0x40000000 = "XenVMMXenVMM")
   - Xen-specific registry/driver artifacts

G. WINE DETECTION:
   - wine_get_version() export in ntdll.dll
   - HKCU\Software\Wine registry key

H. PARALLELS DETECTION:
   - Parallels-specific CPUID and driver artifacts

### MODULE 4 — SANDBOX DETECTION (GENERIC)
1. Username / computer name heuristics (e.g., "SANDBOX", "MALTEST", "VIRUS", "JOHN")
2. Suspicious file name detection (e.g., running as "sample.exe", "malware.exe", "sandbox.exe")
3. Uptime check (sandboxes often have suspiciously short uptime)
4. User interaction check (no mouse movement, no foreground window activity = sandbox)
5. Loaded module count heuristic (real systems have far more loaded DLLs)
6. Disk file count heuristic (sandbox drives often have few files)
7. Recent document count check (real users have recent files)
8. Screen saver configured check (real users configure screen savers)
9. Sleep/delay acceleration detection (sandboxes speed up Sleep() calls)
10. Printer presence check
11. Clipboard content check (sandboxes have empty clipboards)
12. Browser history presence
13. WMI queries for running processes, disk size, and system info cross-validation

### MODULE 5 — ANALYSIS TOOL DETECTION
Scan for presence of ALL of the following by process name, window title, and loaded module:
Debuggers: x64dbg, x32dbg, OllyDbg, WinDbg, IDA Pro, Immunity Debugger, GDB, Ghidra
Disassemblers: IDA Pro, Binary Ninja, Radare2, Ghidra, Hopper, RetDec
Memory Tools: Cheat Engine, TSearch, ArtMoney, GameConqueror
Unpackers: PE-bear, PEiD, Exeinfope, DIE (Detect It Easy), UPX Tool, LordPE, OllyDump
Monitors: Process Monitor, Process Hacker, API Monitor, Wireshark, Fiddler, Sysinternals, RegShot
Inject tools: Extreme Injector, Process Injector variants, ManualMap injectors
Hook detectors: ScyllaHide artifacts (detect anti-anti-debug tools)

### MODULE 6 — CODE INJECTION & MEMORY INTEGRITY
1. Enumerate all threads in own process and detect foreign threads
2. Walk own module's PE sections and validate CRC/hash integrity at runtime
3. Detect inline hooks on critical API functions by checking for JMP/CALL/INT3 prologue overwrite
4. Detect IAT hooks (scan Import Address Table for unexpected redirections)
5. Detect VEH (Vectored Exception Handler) injection by foreign code
6. Anti-dump: Erase PE header from memory at runtime (wipe MZ/PE signature, section headers)
7. Anti-dump: Mangle the SizeOfImage and SizeOfCode fields in memory
8. Detect memory breakpoints via VirtualQuery on own code pages

### MODULE 7 — ANTI-DISASSEMBLY
1. Insert opaque predicates that always evaluate to the same branch but confuse linear disassemblers
2. Use overlapping instruction sequences (junk bytes after conditional jumps)
3. Use CALL/POP-based obfuscation to hide true EIP
4. Insert garbage bytes that are valid x86/x64 instructions but are never executed
5. Use self-modifying code stubs (decrypt critical checks at runtime, re-encrypt after)
6. Misalign function entry points relative to section start

### MODULE 8 — CODE VIRTUALIZATION (VMProtect-style)
Design a custom bytecode VM with:
1. A private instruction set (unique opcodes — not x86)
2. A dispatch loop (interpreter) embedded in the protected binary
3. A compiler/transpiler stage that converts selected C/C++ functions into VM bytecode
4. Encrypted VM bytecode stored in a custom section
5. Per-build randomized opcode mappings (polymorphic VM)
6. Stack-based VM architecture with common arithmetic and control flow opcodes
7. VM self-integrity checks (VM handler table is hashed and verified)

### MODULE 9 — RESPONSE / REACTION SYSTEM
Implement a tiered, deceptive response system:
TIER 1 — SILENT: Set hidden flags that silently corrupt internal state over time (logic bomb style)
TIER 2 — MISDIRECT: Return fake license/valid results to mislead the analyst
TIER 3 — DELAYED CRASH: After N minutes, trigger a structured exception that terminates the process
TIER 4 — HARD TERMINATE: NtTerminateProcess(0, 0) via direct syscall
TIER 5 — KERNEL ESCALATION (optional): Request kernel-level process termination

### MODULE 10 — STEALTH & OBFUSCATION
1. All sensitive strings must be XOR/AES encrypted at compile time and decrypted only at runtime
2. All API calls must be resolved dynamically via custom GetProcAddress reimplementation
3. Use direct syscalls (via syscall instruction) for all sensitive NT calls
4. Randomize check execution order per run
5. Distribute checks across multiple threads with random delays
6. Never use obvious function names — use obfuscated naming or strip symbols entirely

### MODULE 11 — HTTP DEBUGGER & TRAFFIC INTERCEPTION TOOL DETECTION
Detect tools like Fiddler, Charles, Burp Suite, ZAP, mitmproxy, Proxifier, Wireshark, etc.
(A) Process/Window Detection
(B) Certificate Store Inspection (MITM detection)
(C) Driver & Service Detection (npcap.sys, etc.)
(D) Network Stack & Proxy Configuration Analysis
(E) Port Listening Detection
(F) Loaded Module / DLL Inspection

### MODULE 12 — VPN DETECTION
Detect VPNs through Vectors:
12A — VIRTUAL NETWORK ADAPTER (TAP/TUN) DRIVER DETECTION
12B — VPN PROCESS DETECTION
12C — VPN SERVICE DETECTION
12D — VPN CERTIFICATE DETECTION
12E — ROUTING TABLE ANALYSIS

### MODULE 13 — ADVANCED TRAFFIC INTERCEPTION META-DETECTION
13A — SSL/TLS STACK ANOMALY DETECTION (Certificate Pinning)
13B — DETECT PACKET CAPTURE DRIVER ACTIVITY (NPCAP/WINPCAP)
13C — DETECT SOCKS/HTTP PROXY ENV VARIABLES
13D — DETECT PROXIFIER / PROXYCAP (Process-level proxy forcing)
13E — TOR / ANONYMIZATION NETWORK DETECTION
13F — RESPONSE TO NETWORK TOOL DETECTION

## ⚖️ Ethical Disclaimer
This SDK is for legitimate software protection only. Use for malware or harmful software is strictly prohibited.
