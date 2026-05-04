# IronLock Protection SDK - TODO & Roadmap

## Feature Set Integration
- [x] **NotRequiem/antidbg Full Integration**: DONE
    - [x] Implement fully syscalled userland anti-debugging library: DONE
    - [x] Add CLI tool for automated protection of binaries: DONE
    - [x] Port advanced assembly-based stealth techniques from `antidbg`: DONE
- [x] **AdvDebug/AntiCrack-DotNet Full Integration**: DONE
    - [x] Implement `NtUserGetForegroundWindow` window name scanning: DONE
    - [x] Implement `NtSetDebugFilterState` check: DONE
    - [x] Implement Page Guard Breakpoints Detection (PAGE_GUARD): DONE
    - [x] Implement `NtClose` Protected Handle check: DONE
    - [x] Implement OllyDbg Format String exploit protection: DONE
    - [x] Implement patching `DbgUiRemoteBreakin` and `DbgBreakPoint`: DONE
    - [x] Detect specific sandboxes: `Any.run`, `Triage`, `Sandboxie`, etc.: DONE
    - [x] Check `KUSER_SHARED_DATA` for static time values: DONE

## Advanced Features Implemented
- [x] **Hardware Breakpoint Persistence (Feature 1)**: DONE
- [x] **Process Hollowing Detection (Feature 4)**: DONE
- [x] **Injected Thread Detection (Feature 5)**: DONE
- [x] **Syscall Hooking Detection (Feature 6)**: DONE
- [x] **Per-String Encryption Keys (Feature 12)**: DONE
- [x] **Anti-Attach Patching (Feature 17)**: DONE
- [x] **System BSOD Response (Feature 30)**: DONE
- [x] **Fake File Corruption Response (Feature 29)**: DONE
- [x] **Bait Vulnerability Functions (Feature 28)**: DONE
- [x] **IronLock Transpiler (90% Finished)**: DONE
- [x] **Triple Redundant Integrity System**: DONE
- [x] **Function Name Randomization**: DONE
- [x] **IronLock Compiler Engine**: DONE

## Future Roadmap (Next 30+ Features)
1.  [ ] **Kernel-mode protection driver**: Move core checks to Ring 0.
2.  [ ] **Polymorphic VM**: Generate a completely new instruction set per build.
3.  [ ] **Control Flow Flattening (CFF)**: Fully implement LLVM-style CFF in the protector.
4.  [ ] **Import Address Table (IAT) Camouflage**: Encrypt and resolve IAT entries lazily.
5.  [ ] **Instruction Overlapping (Module 7 advanced)**: Full coverage for critical logic.
6.  [ ] **Windows 11 VBS/HVCI Detection**: Deep hypervisor state inspection.
7.  [ ] **HWID Fingerprinting**: Strong hardware-based licensing.
8.  [ ] **Server-Side Heartbeat**: Cloud-integrated protection.
9.  [ ] **Section Name Randomization**: Per-build random PE section names.
10. [ ] **TLS-based Header Restoration**: Move header wiping to earlier in the load process.
... (and 20+ more as planned)
