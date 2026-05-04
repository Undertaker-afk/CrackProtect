# Bypass Analysis & Countermeasures

| Technique | Analyst Method | IronLock Countermeasure |
|-----------|----------------|-------------------------|
| PEB Patching | Setting `BeingDebugged` to 0 | Direct `NtQueryInformationProcess` via syscall. |
| API Hooking | Hooking `IsDebuggerPresent` | Hell's Gate / Halo's Gate direct syscalls to bypass hooks. |
| VM Spoofing | Patching CPUID results | Multi-layered detection (I/O ports, Drivers, Registry, SMBIOS). |
| Single Stepping | Using hardware breakpoints | Periodic checks of `Dr0-Dr7` registers. |
| String Scanning | Searching for "VirtualBox" | All strings are XOR-obfuscated or hashed (FNV-1a). |
| Static Analysis | Linear disassembly | Opaque predicates and junk code insertion. |
| Memory Dumping | Using Scylla / LordPE | PE Header erasure and runtime Mangling. |
| MITM Proxying | Installing custom Root CA | Manual enumeration of the Root Certificate Store. |
