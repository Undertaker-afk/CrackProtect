# IronLock Protection SDK - TODO & Roadmap

## Feature Set Integration
- [x] **NotRequiem/antidbg Full Integration**: DONE
- [x] **AdvDebug/AntiCrack-DotNet Full Integration**: DONE
- [x] **IronLock Compiler Engine (cl-wrapper)**: DONE
- [x] **IronLock Transpiler (Source-to-Bytecode)**: DONE
- [x] **Triple Redundant Integrity System**: DONE
- [x] **Function Name Randomization Suite**: DONE
- [x] **Production-Ready AES-256 (Non-Mock)**: DONE
- [x] **Bait Functions (20+)**: DONE
- [x] **Anti-Attach Patching**: DONE
- [x] **Hell's Gate / Halo's Gate Syscall Discovery**: DONE
- [x] **Manual PEB Export Resolver**: DONE

## Roadmap (Next 30+ Features)
1.  [ ] **Kernel-mode protection driver**: Move core checks to Ring 0.
2.  [ ] **Polymorphic VM**: Generate a completely new instruction set per build.
3.  [ ] **Control Flow Flattening (CFF)**: Fully implement LLVM-style CFF.
4.  [ ] **Import Address Table (IAT) Camouflage**: Encrypt and resolve IAT entries lazily.
5.  [ ] **Windows 11 VBS/HVCI Detection**: Deep hypervisor state inspection.
6.  [ ] **HWID Fingerprinting**: Strong hardware-based licensing.
7.  [ ] **Server-Side Heartbeat**: Cloud-integrated protection.
8.  [ ] **Section Name Randomization**: Per-build random PE section names.
9.  [ ] **TLS-based Header Restoration**: Move header wiping to earlier in the load process.
10. [ ] **Instruction Overlapping (Module 7 advanced)**: Full coverage for critical logic.
11. [ ] **Context-Aware Responses**: Tailor reactions based on the type of threat detected.
12. [ ] **Self-Modifying Detection Code**: Change the detection logic itself at runtime.
13. [ ] **Stealthy Telemetry**: Exfiltrate detection data via covert channels.
14. [ ] **User Interaction Fingerprinting**: Identify human vs. automated sandbox activity.
15. [ ] **Advanced Sandbox Artifact Scanning**: Detect modern sandboxes like Any.run, Triage.
16. [ ] **Hyper-V specific MSR checks**: Detect Hyper-V at the hardware level.
17. [ ] **CPU Thermal Sensor Heuristics**: Differentiate between physical and virtual CPUs.
18. [ ] **GPU Artifact Detection**: Detect virtualized graphics drivers.
19. [ ] **ACPI Table Inspection**: Scan for "SLIC" and other VM-related strings.
20. [ ] **Memory Hook Restoration**: Automatically unhook critical APIs if tampered with.
21. [ ] **VEH Chain Protection**: Prevent hijacking of the Vectored Exception Handler chain.
22. [ ] **Advanced Anti-Dump**: Mangle module lists and memory maps.
23. [ ] **Fake Module Injection**: Inject decoys to confuse static analysis tools.
24. [ ] **Symbol Strip & Mangle**: Remove and scramble all metadata from the final binary.
25. [ ] **Multi-Layered Binary Encryption**: Encrypt the protected binary with multiple keys.
26. [ ] **Anti-Debugging via Exception Handling**: Abuse exception flow to detect debuggers.
27. [ ] **LDR Hook Detection**: Monitor for hooks in the Loader functions of ntdll.
28. [ ] **Custom PE Loader**: Implement a private loader to avoid system artifacts.
29. [ ] **Anti-Analysis via Threading**: Use complex thread inter-dependencies to break debuggers.
30. [ ] **Integrity Guard integration**: Leverage Windows Control Flow Guard (CFG).
31. [ ] **UEFI Level Protection**: Secure the boot process before the OS loads.
