# IronLock Protection SDK - TODO & Future Roadmap

## Feature Set Integration
- [ ] **NotRequiem/antidbg Full Integration**:
    - [ ] Implement fully syscalled userland anti-debugging library.
    - [ ] Add CLI tool for automated protection of binaries.
    - [ ] Port advanced assembly-based stealth techniques from `antidbg`.
- [ ] **AdvDebug/AntiCrack-DotNet Full Integration**:
    - [ ] Implement `NtUserGetForegroundWindow` window name scanning.
    - [ ] Implement `NtSetDebugFilterState` check.
    - [ ] Implement Page Guard Breakpoints Detection (PAGE_GUARD).
    - [ ] Implement `NtClose` Protected Handle check.
    - [ ] Implement OllyDbg Format String exploit protection.
    - [ ] Implement patching `DbgUiRemoteBreakin` and `DbgBreakPoint` to prevent debugger attaching.
    - [ ] Detect specific sandboxes: `Any.run`, `Triage`, `Sandboxie`, `Comodo Container`, `Qihoo360`, `Cuckoo`.
    - [ ] Check `KUSER_SHARED_DATA` for static time values (common in emulators).
    - [ ] Scan for virtual devices and ports indicative of VMs.

## 30+ Advanced Features to Improve IronLock
1.  **Hardware Breakpoint Persistence**: Regularly verify and reset `Dr0-Dr7` registers.
2.  **SEH Chain Validation**: Detect debuggers that modify the Structured Exception Handling chain.
3.  **Polymorphic Detection Stubs**: Mutate detection logic at runtime to evade signature-based bypasses.
4.  **Process Hollowing Detection**: Verify own process image against disk using raw file I/O.
5.  **Injected Thread Detection**: Walk thread stacks to find entry points outside of legitimate modules.
6.  **Syscall Hooking Detection**: Scan `ntdll.dll` in memory for any unexpected `JMP` or `INT3` at syscall entry points.
7.  **VEH Priority Enforcement**: Ensure IronLock's Vectored Exception Handler is always first in the chain.
8.  **HWID Fingerprinting**: Bind the protected application to a specific machine's hardware ID.
9.  **Server-Side Heartbeat**: Require periodic encrypted pings to a remote server for continued execution.
10. **Section Name Randomization**: Rename PE sections (e.g., `.text`, `.data`) to random strings per build.
11. **TLS-based Header Restoration**: Use Thread Local Storage callbacks to restore or erase headers dynamically.
12. **Per-String Encryption Keys**: Use a unique AES key and IV for every single string in the binary.
13. **Instruction Overlapping**: Apply Module 7 techniques to all critical SDK logic.
14. **Extended WMI VM Queries**: Query `Win32_BaseBoard`, `Win32_VideoController`, and `Win32_IDEController`.
15. **UI Interaction Heuristics**: Detect sandboxes by checking for mouse trails, double clicks, and keyboard speed.
16. **Sandbox Path Heuristics**: Scan for common sandbox artifacts like `C:\samples`, `C:\analysis`, etc.
17. **Anti-Attach Patching**: Overwrite `DbgUiRemoteBreakin` with `TerminateProcess` logic.
18. **ScyllaHide Artifact Detection**: Scan for specific hooks or registry keys used by `ScyllaHide`.
19. **Kernel Debugger via SystemModuleInformation**: Enumerate loaded drivers to find `kdcom.dll` or similar.
20. **ProxyCap/Proxifier Detection**: Specifically detect process-level proxy forcing tools.
21. **Certificate Pinning Secondary Domains**: Pin certificates for update servers and telemetry endpoints.
22. **Wireshark NPCAP Detection**: Check the running state and filter status of the `npcap` driver.
23. **Multi-Stage CRC Validation**: Implement nested CRC checks where one module verifies another's integrity.
24. **ntdll.dll Disk vs Memory Comparison**: Detect `ntdll` hooks by comparing against the file on disk.
25. **Custom Bytecode JIT**: Implement a small JIT compiler for the VM module to improve performance and obfuscation.
26. **VM Floating Point Support**: Add opcodes for floating point arithmetic to the custom VM.
27. **Control Flow Flattening**: Apply flattening to the VM's interpreter loop and dispatch table.
28. **Bait Vulnerability Functions**: Implement functions that appear vulnerable to common exploits to trap analysts.
29. **Fake File Corruption Response**: Simulate file system corruption when a debugger is detected to scare analysts.
30. **System BSOD Response**: Trigger a blue screen using `NtRaiseHardError` as a TIER 5 response.
31. **Windows 11 VBS/HVCI Detection**: Detect if Virtualization-Based Security or Hypervisor-Enforced Code Integrity is active.
32. **GUI Configuration Tool**: Create a standalone builder tool to configure SDK features via a UI.
33. **Import Address Table Camouflage**: Scramble the IAT and resolve imports lazily at runtime.

## Compiler & Tooling
- [ ] **Full IronLock Transpiler**: Build a Clang-based tool to automatically virtualize marked C++ functions.
- [ ] **Automated Build System**: Integrate string encryption and opcode randomization into the CI/CD pipeline.
