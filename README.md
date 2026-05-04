You are an expert low-level systems security engineer specializing in software 
protection, reverse engineering countermeasures, and anti-tamper design. 
Your task is to architect and implement a comprehensive, production-grade 
anti-crack and anti-debugging protection library in C/C++ (targeting Windows 
x86/x64), comparable in depth and coverage to VMProtect and the full al-khaser 
detection suite.

=======================================================================
 PROJECT GOAL
=======================================================================
Build a modular, embeddable protection SDK that detects and responds to:
  - Debuggers (user-mode and kernel-mode)
  - Virtual machines and sandbox environments
  - Analysis tools (IDA Pro, x64dbg, Cheat Engine, Ghidra, OllyDbg, etc.)
  - Code injection attempts
  - Memory dumping attempts
  - Anti-disassembly bypass attempts
  - Timing-based sandbox evasion
  - Code tampering / integrity violations

The system must be MODULAR (each check is a standalone module), STEALTHY 
(checks must not appear obvious to static analysis), and RESILIENT 
(responses must be non-trivial to bypass).

=======================================================================
 MODULE 1 — ANTI-DEBUGGING (USER MODE)
=======================================================================
Implement ALL of the following debugger detection methods:

1. IsDebuggerPresent() API check (PEB.BeingDebugged flag)
2. CheckRemoteDebuggerPresent() via NtQueryInformationProcess()
3. ProcessDebugPort check (NtQueryInformationProcess with 
   ProcessDebugPort = 0x7)
4. ProcessDebugObjectHandle check
5. ProcessDebugFlags check (NtQueryInformationProcess 
   ProcessDebugFlags = 0x1F)
6. CloseHandle() with invalid handle → detect 
   EXCEPTION_INVALID_HANDLE (0xC0000008)
7. NtClose() with invalid handle (direct syscall variant)
8. Heap flags inspection (PEB.NtGlobalFlag, heap ForceFlags)
9. INT 3 / 0xCC software breakpoint scanning in own code regions
10. Hardware breakpoint detection via CONTEXT.Dr0–Dr3 debug registers
11. RDTSC-based timing delta analysis 
    (detect slowdown from single-step / breakpoint traps)
12. GetTickCount / QueryPerformanceCounter timing cross-check
13. OutputDebugString() trick (error code behavior differs 
    under debugger)
14. Guard page exception trick using VirtualProtect() + 
    GUARD_PAGE flag
15. TLS (Thread Local Storage) callback abuse for early 
    pre-EntryPoint detection
16. UnhandledExceptionFilter() presence check
17. Trap Flag (TF) single-step exception trick
18. Parent process name validation 
    (legitimate parent = explorer.exe, not a debugger)
19. SeDebugPrivilege check (debuggers often have this privilege)
20. NtSetInformationThread with ThreadHideFromDebugger 
    (and detect if this is already applied by an attacker)
21. DbgBreakPoint / DbgUiRemoteBreakin hook integrity check
22. Heap handle count comparison (debugger inflates handle count)
23. "Heaven's Gate" 32-to-64-bit segment switch detection 
    (detect if analysis is being done in 32-bit mode on 64-bit code)

=======================================================================
 MODULE 2 — ANTI-DEBUGGING (KERNEL MODE / DRIVER-LEVEL CHECKS)
=======================================================================
1. KdDebuggerEnabled / KdDebuggerNotPresent flags 
   (via NtQuerySystemInformation or shared kernel data)
2. Check SharedUserData!KdDebuggerEnabled
3. Detect kernel debugger via KUSER_SHARED_DATA
4. NtQuerySystemInformation(SystemKernelDebuggerInformation)
5. Detect WinDbg kernel sessions via driver heartbeat absence
6. Check for presence of known kernel debug drivers 
   (e.g., dbgeng.dll, kd.exe artifacts)

=======================================================================
 MODULE 3 — VIRTUAL MACHINE DETECTION
=======================================================================
Implement detection for ALL of the following hypervisors/emulators,
matching al-khaser's full coverage:

A. GENERIC VM DETECTION:
   - CPUID hypervisor bit (ECX bit 31 of leaf 1)
   - CPUID hypervisor vendor string (leaf 0x40000000)
   - SMBIOS/DMI string inspection 
     (BIOS vendor, system family, system UUID, OEM fields)
   - Raw SMBIOS via WMI (Win32_BIOS, Win32_ComputerSystem)
   - Power state enumeration 
     (most VMs don't support S1–S4 power states)
   - Disk geometry inspection 
     (VM disk sizes are often unrealistically round)
   - Total physical disk space heuristic 
     (sandbox drives are often small)
   - Lack of battery / thermal sensors 
     (most VMs have no power management)
   - MAC address OUI check against known VM vendors
   - Screen resolution heuristic (VMs often use standard low-res)
   - Loaded driver/module list inspection 
     (vmmouse.sys, vmhgfs.sys, vboxguest.sys, etc.)
   - Registry key artifact scanning 
     (HKLM\SOFTWARE\VMware Inc., VirtualBox, etc.)
   - Known VM process name scanning 
     (vmtoolsd.exe, vboxservice.exe, etc.)
   - Genuine Windows installation check 
     (NtQueryLicenseValue with Kernel-VMDetection-Private)

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

=======================================================================
 MODULE 4 — SANDBOX DETECTION (GENERIC)
=======================================================================
1. Username / computer name heuristics 
   (e.g., "SANDBOX", "MALTEST", "VIRUS", "JOHN")
2. Suspicious file name detection 
   (e.g., running as "sample.exe", "malware.exe", "sandbox.exe")
3. Uptime check (sandboxes often have suspiciously short uptime)
4. User interaction check 
   (no mouse movement, no foreground window activity = sandbox)
5. Loaded module count heuristic 
   (real systems have far more loaded DLLs)
6. Disk file count heuristic 
   (sandbox drives often have few files)
7. Recent document count check 
   (real users have recent files)
8. Screen saver configured check 
   (real users configure screen savers)
9. Sleep/delay acceleration detection 
   (sandboxes speed up Sleep() calls — detect via cross-checking)
10. Printer presence check
11. Clipboard content check (sandboxes have empty clipboards)
12. Browser history presence
13. WMI queries for running processes, 
    disk size, and system info cross-validation

=======================================================================
 MODULE 5 — ANALYSIS TOOL DETECTION
=======================================================================
Scan for presence of ALL of the following by process name, 
window title, and loaded module:

Debuggers:      x64dbg, x32dbg, OllyDbg, WinDbg, IDA Pro, 
                Immunity Debugger, GDB, Ghidra (server process)

Disassemblers:  IDA Pro, Binary Ninja, Radare2, Ghidra, 
                Hopper, RetDec

Memory Tools:   Cheat Engine, TSearch, ArtMoney, GameConqueror

Unpackers:      PE-bear, PEiD, Exeinfope, DIE (Detect It Easy), 
                UPX Tool, LordPE, OllyDump

Monitors:       Process Monitor, Process Hacker, API Monitor, 
                Wireshark, Fiddler, Sysinternals Suite tools, 
                RegShot

Inject tools:   Extreme Injector, Process Injector variants, 
                ManualMap injectors

Hook detectors: ScyllaHide artifacts (detect anti-anti-debug tools)

=======================================================================
 MODULE 6 — CODE INJECTION & MEMORY INTEGRITY
=======================================================================
1. Enumerate all threads in own process and detect foreign threads
2. Walk own module's PE sections and validate CRC/hash 
   integrity at runtime
3. Detect inline hooks on critical API functions 
   (NtQueryInformationProcess, IsDebuggerPresent, etc.) 
   by checking for JMP/CALL/INT3 prologue overwrite
4. Detect IAT hooks (scan Import Address Table for unexpected 
   redirections outside known module ranges)
5. Detect VEH (Vectored Exception Handler) injection 
   by foreign code
6. Anti-dump: Erase PE header from memory at runtime 
   (wipe MZ/PE signature, section headers)
7. Anti-dump: Mangle the SizeOfImage and SizeOfCode 
   fields in memory
8. Detect memory breakpoints via 
   VirtualQuery on own code pages (PAGE_EXECUTE -> PAGE_GUARD)

=======================================================================
 MODULE 7 — ANTI-DISASSEMBLY
=======================================================================
1. Insert opaque predicates that always evaluate to the same 
   branch but confuse linear disassemblers
2. Use overlapping instruction sequences 
   (junk bytes after conditional jumps)
3. Use CALL/POP-based obfuscation to hide true EIP
4. Insert garbage bytes that are valid x86/x64 instructions 
   but are never executed
5. Use self-modifying code stubs 
   (decrypt critical checks at runtime, re-encrypt after)
6. Misalign function entry points relative to section start

=======================================================================
 MODULE 8 — CODE VIRTUALIZATION (VMProtect-style)
=======================================================================
Design a custom bytecode VM with:
1. A private instruction set (unique opcodes — not x86)
2. A dispatch loop (interpreter) embedded in the protected binary
3. A compiler/transpiler stage that converts selected 
   C/C++ functions into VM bytecode
4. Encrypted VM bytecode stored in a custom section
5. Per-build randomized opcode mappings 
   (polymorphic VM — opcodes change each compile)
6. Stack-based VM architecture with:
   - PUSH / POP / ADD / SUB / XOR / AND / OR / CMP / JMP / 
     CALL / RET / LOAD / STORE custom opcodes
7. VM self-integrity checks 
   (VM handler table is hashed and verified before dispatch)

=======================================================================
 MODULE 9 — RESPONSE / REACTION SYSTEM
=======================================================================
When any check is triggered, do NOT immediately crash (too obvious).
Instead implement a tiered, deceptive response system:

TIER 1 — SILENT: Set hidden flags that silently corrupt 
          internal state over time (logic bomb style)
TIER 2 — MISDIRECT: Return fake license/valid results to 
          mislead the analyst into thinking bypass worked
TIER 3 — DELAYED CRASH: After N minutes, trigger a structured 
          exception that terminates the process
TIER 4 — HARD TERMINATE: NtTerminateProcess(0, 0) via 
          direct syscall (bypass hooks on TerminateProcess)
TIER 5 — KERNEL ESCALATION (optional): If driver present, 
          request kernel-level process termination

All responses must be triggered via indirect function calls 
and obfuscated control flow to resist static analysis.

=======================================================================
 MODULE 10 — STEALTH & OBFUSCATION
=======================================================================
1. All sensitive strings (VM artifact names, process names, 
   registry paths) must be XOR/AES encrypted at compile time 
   and decrypted only at runtime into stack buffers 
   (never stored plaintext in binary)
2. All API calls must be resolved dynamically via:
   - Custom GetProcAddress reimplementation using PEB walking
   - Hashed API names (FNV-1a or DJB2) instead of strings
3. Use direct syscalls (via syscall instruction) for all 
   sensitive NT calls — bypass userland hooks entirely
4. Randomize check execution order per run 
   (seed from RDTSC + process ID)
5. Distribute checks across multiple threads with random delays
6. Never use obvious function names — use obfuscated naming 
   or strip symbols entirely

=======================================================================
 MODULE 11 — HTTP DEBUGGER & TRAFFIC INTERCEPTION TOOL DETECTION
=======================================================================
Detect ALL tools capable of intercepting, inspecting, or modifying 
HTTP/HTTPS traffic. Use a MULTI-LAYER approach combining:
  (A) Process/Window Detection
  (B) Certificate Store Inspection
  (C) Driver & Service Detection
  (D) Network Stack & Proxy Configuration Analysis
  (E) Port Listening Detection
  (F) Loaded Module / DLL Inspection

-----------------------------------------------------------------------
 11A — PROCESS & WINDOW TITLE DETECTION
-----------------------------------------------------------------------
Enumerate all running processes AND visible/hidden window titles.
Flag detection if ANY of the following are found:

HTTP PROXY / DEBUGGER TOOLS:
  Processes:
    - fiddler.exe          (Telerik/Progress Fiddler Classic)
    - fiddler4.exe
    - fiddlercore.exe
    - charlescerts.exe     (Charles Web Debugging Proxy)
    - charles.exe
    - burpsuite.exe        (PortSwigger Burp Suite)
    - burp.exe
    - zap.exe              (OWASP ZAP / Zed Attack Proxy)
    - owasp_zap.exe
    - mitmproxy.exe        (mitmproxy)
    - mitmdump.exe
    - mitmweb.exe
    - proxifier.exe        (Proxifier - force-routes all traffic)
    - proxycap.exe         (ProxyCap)
    - httpdebugger.exe     (HTTP Debugger Pro)
    - reqresplayerpro.exe
    - apimonitor*.exe      (API Monitor — hooks WinSock/WinHTTP)
    - wireshark.exe        (packet capture)
    - tshark.exe
    - rawcap.exe
    - networkmonitor.exe   (Microsoft Network Monitor)
    - netmon.exe
    - capsa.exe
    - commview.exe
    - nmap.exe
    - httpwatch*.exe       (HttpWatch)
    - postman.exe          (Postman — can be used to replay/forge)
    - insomnia.exe
    - hoppscotch*.exe
    - advanced_rest_client.exe
    - soapui.exe

  Window Titles (substring match, case-insensitive):
    - "Fiddler"
    - "Charles"
    - "Burp Suite"
    - "OWASP ZAP"
    - "mitmproxy"
    - "Proxifier"
    - "Wireshark"
    - "HTTP Debugger"
    - "Packet Capture"
    - "Network Monitor"

  Implementation:
    - Use CreateToolhelp32Snapshot() + Process32Next() for processes
    - Use EnumWindows() + GetWindowText() for window titles
    - All target strings must be AES/XOR encrypted at compile time, 
      decrypted only into stack-allocated buffers at runtime
    - Hash-compare process names using FNV-1a to avoid plaintext 
      strings in binary

-----------------------------------------------------------------------
 11B — SSL/TLS CERTIFICATE STORE INSPECTION
-----------------------------------------------------------------------
HTTP intercept tools operate as Man-in-the-Middle (MITM) proxies. 
To intercept HTTPS traffic, they MUST install a custom root CA 
certificate into the Windows certificate store.

Detect this by:

1. ENUMERATE THE TRUSTED ROOT CA STORE:
   Open the certificate store via CertOpenSystemStore(NULL, "ROOT")
   Iterate ALL certificates with CertEnumCertificatesInStore()
   
   For each certificate, extract:
     - Subject CN (Common Name)
     - Issuer CN
     - Thumbprint (SHA-1 and SHA-256)
     - Subject Organization (O=)
     - Subject Alternative Names
     - Key Usage flags
     - "Valid From" date (abnormally new self-signed root = suspicious)
     - Signature Algorithm
   
   FLAG as suspicious if any certificate matches:
   
   KNOWN TOOL CERTIFICATE FINGERPRINTS / SUBJECTS:
     - CN = "DO_NOT_TRUST_FiddlerRoot"    (Fiddler Classic default CA)
     - CN = "FiddlerRoot"
     - CN = "Fiddler"  (any variant)
     - CN = "Charles Proxy CA"
     - O  = "XK72 Ltd"                   (Charles Proxy publisher)
     - CN = "PortSwigger CA"              (Burp Suite CA)
     - O  = "PortSwigger Ltd"
     - CN = "OWASP Zed Attack Proxy Root CA"
     - CN = "mitmproxy"
     - CN containing "mitm"
     - CN = "Proxifier"
     - CN = "Fiddler Everywhere Root Certificate Authority"
     - CN = "HTTP Debugger Root CA"
     - Any self-signed root CA issued within the last 2 years 
       that was NOT issued by a well-known public CA (Microsoft, 
       DigiCert, GlobalSign, Sectigo, Entrust, etc.)

2. CHECK THE "CA" STORE AND "MY" STORE AS WELL:
   Repeat the same enumeration for:
     CertOpenSystemStore(NULL, "CA")
     CertOpenSystemStore(NULL, "MY")

3. DETECT CERTIFICATE INJECTION METHODS:
   - Scan HKCU\Software\Microsoft\SystemCertificates\Root\Certificates
     for recently added root certificates 
     (compare last-write timestamp vs. OS install date)
   - Scan HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates
     for the same
   - Scan HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root
     (Group Policy injected certificates — enterprise MITM proxies 
     like ZScaler, BlueCoat, Forcepoint install here)

4. DETECT ENTERPRISE / CORPORATE MITM PROXIES:
   Also flag certificates from known enterprise SSL inspection proxies:
     - CN or O containing "Zscaler"
     - CN or O containing "Blue Coat"
     - CN or O containing "Forcepoint"
     - CN or O containing "Cisco Umbrella"
     - CN or O containing "Symantec SSL"
     - CN or O containing "Netskope"
     - CN or O containing "iboss"
   Note: Enterprise proxies are ALSO a threat to application 
   confidentiality and must be detected even if legitimate.

5. DETECT CERTIFICATE PINNING BYPASS TOOLS:
   Check for presence of:
     - frida-gadget DLLs injected into own process memory
     - ssl_logger artifacts
     - Any loaded DLL whose name or path contains 
       "frida", "objection", "ssl_kill", "certpatch", "sslstrip"

-----------------------------------------------------------------------
 11C — DRIVER-LEVEL DETECTION (HTTP INTERCEPTION)
-----------------------------------------------------------------------
Some advanced proxy/capture tools install kernel drivers or 
NDIS filter drivers to intercept traffic at a lower level 
than WinSock. Detect these by:

1. ENUMERATE KERNEL DRIVERS VIA SCM:
   Use OpenSCManager() + EnumServicesStatusEx() with 
   SERVICE_DRIVER type to list all installed kernel drivers.
   
   Cross-reference against known tool drivers:
     - npf.sys / npcap.sys (WinPcap/Npcap — used by Wireshark)
     - ndiscap.sys         (Windows built-in packet capture — 
                            presence indicates capture session active)
     - wfplwf.sys          (WFP NDIS lightweight filter)
     - pktFilter.sys       (Packet filtering driver artifacts)
     - klif.sys            (Kaspersky traffic inspection)
     - inspect.sys         (generic inspection driver name pattern)
     
   Use NtQuerySystemInformation(SystemModuleInformation) to list 
   ALL loaded kernel modules and cross-check against:
     - Any .sys file not in %SystemRoot%\System32\drivers\ 
       that is loaded = high suspicion
     - Drivers signed by known tool vendors 
       (WinPcap, Npcap Organization, etc.)

2. WFP (WINDOWS FILTERING PLATFORM) CALLOUT DETECTION:
   Advanced interception tools register WFP callouts to 
   intercept traffic at the kernel level.
   Use FwpmCalloutEnum0() (via fwpuclnt.dll, resolved dynamically) 
   to enumerate registered WFP callout drivers.
   Flag any callout registered by a GUID or provider not 
   belonging to Microsoft or known legitimate software.

3. NDIS FILTER DETECTION:
   Enumerate:
   HKLM\SYSTEM\CurrentControlSet\Control\Network\
   {4D36E974-E325-11CE-BFC1-08002BE10318}
   for installed NDIS filter drivers. Flag unknown filters.

-----------------------------------------------------------------------
 11D — NETWORK STACK & PROXY CONFIGURATION DETECTION
-----------------------------------------------------------------------
HTTP intercept tools SET THEMSELVES as the system proxy.
Detect this by inspecting both Windows proxy stacks:

1. WININET PROXY DETECTION (User-level):
   Use WinHttpGetIEProxyConfigForCurrentUser() to retrieve:
     - fAutoDetect (WPAD enabled?)
     - lpszAutoConfigUrl (PAC file URL set?)
     - lpszProxy (static proxy set?)
     - lpszProxyBypass
   
   FLAG if:
     - lpszProxy is set to 127.0.0.1 or localhost 
       (classic local MITM proxy redirect)
     - lpszProxy port matches known tool default ports:
         8888  → Fiddler Classic / Charles
         8080  → Burp Suite / ZAP / mitmproxy
         8081  → Proxifier default
         8888  → HTTP Debugger Pro
         10809 → Proxifier alternative
     - lpszAutoConfigUrl points to a local PAC file 
       (file:// or http://127.0.0.1/...)

2. WINHTTP PROXY DETECTION (System-level):
   Use WinHttpGetDefaultProxyConfiguration() with 
   WINHTTP_PROXY_INFO structure to read:
     - dwAccessType (WINHTTP_ACCESS_TYPE_NAMED_PROXY?)
     - lpszProxy
     - lpszProxyBypass
   Same flagging logic as WinINet above.

3. REGISTRY-LEVEL PROXY KEYS:
   Read directly (without using API, to defeat API hooks):
     HKCU\Software\Microsoft\Windows\CurrentVersion\
     Internet Settings\:
       ProxyEnable   (DWORD: 0 or 1)
       ProxyServer   (string: "127.0.0.1:8888" etc.)
       AutoConfigURL (string: PAC file URL)
       ProxyOverride (bypass list)
   
   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
   Internet Settings\Connections\WinHttpSettings
     (raw binary blob — parse manually to extract proxy address)

4. LSP (LAYERED SERVICE PROVIDER) / WINSOCK CATALOG INSPECTION:
   Use WSAEnumProtocols() to enumerate the Winsock protocol chain.
   Any unknown LSP installed between the application and the 
   network stack is a strong indicator of traffic interception 
   (legacy technique used by older MITM tools).

5. DETECT ACTIVE LOCAL LISTENERS ON KNOWN PROXY PORTS:
   Use GetExtendedTcpTable() with TCP_TABLE_OWNER_PID_LISTENER 
   to enumerate all TCP listening ports.
   If any process is listening on:
     127.0.0.1:8080, :8888, :8081, :9999, :10809, :7777, :3128
   retrieve the owning PID and cross-check against 
   known tool process names.
   Also check if YOUR OWN PROCESS has its traffic 
   being redirected to any such local port.

6. DNS POISONING / HOSTS FILE INSPECTION:
   Read %SystemRoot%\System32\drivers\etc\hosts
   Flag any entries redirecting external domains to 127.0.0.1 
   (a technique used to redirect traffic through a local proxy).

=======================================================================
 MODULE 12 — VPN DETECTION
=======================================================================
VPNs can be used to:
  (a) Hide analyst identity / location
  (b) Reroute traffic to evade geo-checks
  (c) Tunnel traffic to bypass network-level protections
  (d) Operate alongside traffic capture tools

Detect VPNs through ALL of the following vectors:

-----------------------------------------------------------------------
 12A — VIRTUAL NETWORK ADAPTER (TAP/TUN) DRIVER DETECTION
-----------------------------------------------------------------------
VPN clients install virtual network adapters to tunnel traffic.
These are software-only adapters with no physical hardware.

1. ENUMERATE NETWORK ADAPTERS:
   Use GetAdaptersInfo() or GetAdaptersAddresses() to list 
   all network interfaces. For each adapter:
     - Check AdapterType: IF = MIB_IF_TYPE_OTHER or 
       IF_TYPE_TUNNEL = strong indicator of VPN
     - Check Description string against known VPN adapter names:

   KNOWN VPN VIRTUAL ADAPTER NAME PATTERNS (substring match):
     - "TAP-Windows Adapter"      (OpenVPN legacy - tap0901)
     - "TAP-Windows V9"
     - "Wintun Userspace Tunnel"  (OpenVPN modern WireGuard-style)
     - "WireGuard Tunnel"         (WireGuard)
     - "Mullvad"
     - "ExpressVPN"
     - "NordVPN"
     - "ProtonVPN"
     - "Surfshark"
     - "CyberGhost"
     - "PIA" / "Private Internet Access"
     - "Hotspot Shield"
     - "TunnelBear"
     - "IPVanish"
     - "Windscribe"
     - "Cisco AnyConnect"
     - "Cisco VPN Adapter"
     - "Juniper Networks Virtual Adapter"
     - "Pulse Secure"
     - "GlobalProtect"            (Palo Alto Networks)
     - "Fortinet SSL VPN"
     - "SonicWALL Virtual NIC"
     - "OpenVPN"
     - "IVPN"
     - "AirVPN"
     - "hide.me VPN"
     - "VPN"                      (generic pattern — flag for review)
     - "Virtual"                  (combined with non-Microsoft publisher)

2. REGISTRY ENUMERATION OF VIRTUAL ADAPTERS:
   Enumerate:
   HKLM\SYSTEM\CurrentControlSet\Enum\Root\NET\
   For each subkey, read "HardwareID" value.
   Known VPN hardware IDs:
     - "tap0901"     (OpenVPN TAP legacy)
     - "tap0801"
     - "wintun"      (WireGuard / OpenVPN modern)
     - "vpnux"
     - "ndisredirector"
   
   Also enumerate:
   HKLM\SYSTEM\CurrentControlSet\Control\Class\
   {4D36E972-E325-11CE-BFC1-08002BE10318}\
   For each subkey check "MatchingDeviceId" and 
   "ProviderName" for VPN vendor strings.

3. TAP/TUN DRIVER FILE PRESENCE:
   Check for existence of:
     %SystemRoot%\System32\drivers\tap0901.sys
     %SystemRoot%\System32\drivers\wintun.sys
     %SystemRoot%\System32\drivers\tun.sys
     %SystemRoot%\System32\drivers\ovpn*.sys
     %SystemRoot%\System32\drivers\NordVPN*.sys
     %SystemRoot%\System32\drivers\mullvad*.sys
     (and equivalent paths in %SystemRoot%\SysWOW64\drivers\)

-----------------------------------------------------------------------
 12B — VPN PROCESS DETECTION
-----------------------------------------------------------------------
Scan running processes for known VPN client executables:

    openvpn.exe            (OpenVPN daemon)
    openvpn-gui.exe
    wg.exe / wireguard.exe (WireGuard)
    nordvpn.exe / nordvpnd.exe
    expressvpn.exe / expressvpnd.exe
    protonvpn.exe / protonvpnd.exe
    surfshark.exe
    cyberghostvpn.exe
    pia-client.exe / privateinternetaccess.exe
    hotspotshield.exe
    tunnelbear.exe
    windscribe.exe
    ipvanish.exe
    vpnui.exe               (Cisco AnyConnect)
    vpnagent.exe
    cstub.exe               (Cisco AnyConnect stub)
    pangpa.exe              (GlobalProtect - Palo Alto)
    pangps.exe
    PulseSecure.exe
    dsNcService.exe         (Juniper/Pulse)
    FortiSSLVPNdaemon.exe   (Fortinet)
    SoftEtherVPN*.exe
    outline.exe             (Outline VPN)
    psiphon*.exe            (Psiphon circumvention tool)
    lantern.exe             (Lantern circumvention tool)
    shadowsocks*.exe        (ShadowSocks proxy/VPN)
    v2ray.exe               (V2Ray proxy)
    xray.exe                (Xray proxy)
    clash.exe / clashx.exe  (Clash proxy)
    tor.exe                 (Tor network)
    torbrowser*.exe
    obfs4proxy.exe          (Tor obfuscation bridge)
    i2p.exe                 (I2P anonymity network)
    freegate*.exe
    ultrasurf*.exe

-----------------------------------------------------------------------
 12C — VPN SERVICE DETECTION
-----------------------------------------------------------------------
Use OpenSCManager() + EnumServicesStatusEx() to list all services.
Cross-check service names and display names against:

    NordVPN Service
    ExpressVPN
    ProtonVPN Service
    Surfshark Service
    CyberGhost VPN
    Private Internet Access
    OpenVPN Service / OpenVPNService
    WireGuardTunnel$*
    Mullvad VPN
    Cisco AnyConnect VPN Agent
    GlobalProtect Gateway
    PulseSecure
    FortiClient VPN
    SonicWALL VPN
    Hotspot Shield Service

-----------------------------------------------------------------------
 12D — VPN CERTIFICATE DETECTION
-----------------------------------------------------------------------
VPN clients (especially enterprise ones) install their OWN 
root CA certificates for encrypted tunnel verification. 
Cross-check the Windows ROOT certificate store (see Module 11B) 
against VPN-related CAs:

    - CN or O containing "OpenVPN"
    - CN or O containing "NordVPN"
    - CN or O containing "ExpressVPN"
    - CN or O containing "ProtonVPN"
    - CN or O containing "Cisco Systems"    (AnyConnect PKI CA)
    - CN or O containing "Palo Alto Networks"
    - CN or O containing "Pulse Secure"
    - CN or O containing "Fortinet"
    - CN or O containing "WireGuard"
    - Any self-signed CA certificate installed post-OS-install 
      that is not from a recognized commercial CA authority

-----------------------------------------------------------------------
 12E — ROUTING TABLE ANALYSIS (VPN ROUTE HIJACKING)
-----------------------------------------------------------------------
VPNs modify the Windows routing table to redirect all or 
most traffic through the VPN tunnel. Detect this by:

1. Use GetIpForwardTable2() to enumerate the routing table.
2. Flag if:
   - A default route (0.0.0.0/0) exists pointing to a 
     non-physical adapter (e.g., TAP or TUN adapter)
   - Multiple conflicting default routes exist 
     (VPN split-tunneling artifact)
   - Gateway IP is in an RFC5737 / RFC1918 private range 
     but the primary NIC is public-facing

3. Use GetBestRoute2() to determine the actual egress 
   interface for a known external IP. If the result is 
   a virtual adapter, VPN is active.

=======================================================================
 MODULE 13 — ADVANCED TRAFFIC INTERCEPTION META-DETECTION
=======================================================================
Cover edge cases, advanced tools, and protocol-level anomalies:

-----------------------------------------------------------------------
 13A — SSL/TLS STACK ANOMALY DETECTION
-----------------------------------------------------------------------
When a MITM proxy intercepts HTTPS, the TLS session seen by 
the application is NOT the original server certificate.
Detect this by performing a SELF-TLS-VALIDATION:

1. Connect to a known, pinned HTTPS endpoint 
   (can be your own server with a known certificate).
2. Retrieve the presented certificate chain using 
   WinHTTP or a raw TLS handshake (via Schannel / SspiCli).
3. Compare:
   - Certificate thumbprint (SHA-256) against a 
     hardcoded known-good value
   - Certificate chain depth (MITM often introduces 
     an extra intermediate CA)
   - Issuer CN against expected issuer
4. IF ANY mismatch → MITM interception detected.

This is CERTIFICATE PINNING implemented defensively.
Store pinned certificate hashes as compile-time encrypted 
constants — never as plaintext strings.

-----------------------------------------------------------------------
 13B — DETECT PACKET CAPTURE DRIVER ACTIVITY (NPCAP/WINPCAP)
-----------------------------------------------------------------------
1. Check for presence and running state of:
     - npf.sys     (WinPcap — legacy)
     - npcap.sys   (Npcap — modern, used by Wireshark)
   via SCM (QueryServiceStatus) and driver file presence.

2. Check loaded kernel module list via 
   NtQuerySystemInformation(SystemModuleInformation) 
   for the above driver names.

3. Check for Npcap/WinPcap DLLs loaded in current process:
     - Packet.dll
     - wpcap.dll
     - NPcap.dll
   Use Module32Next() to walk the loaded module list.

4. Check registry for WinPcap/Npcap installation:
     HKLM\SOFTWARE\WinPcap
     HKLM\SOFTWARE\Npcap

-----------------------------------------------------------------------
 13C — DETECT SOCKS/HTTP PROXY ENV VARIABLES
-----------------------------------------------------------------------
Some tools set proxy environment variables rather than 
system settings. Read and inspect:
    - HTTP_PROXY
    - HTTPS_PROXY
    - http_proxy
    - https_proxy
    - ALL_PROXY
    - SOCKS_PROXY
    - NO_PROXY

Use GetEnvironmentVariable() for each.
Flag if any points to 127.0.0.1 with known tool ports.

-----------------------------------------------------------------------
 13D — DETECT PROXIFIER / PROXYCAP (PROCESS-LEVEL PROXY FORCING)
-----------------------------------------------------------------------
Tools like Proxifier and ProxyCap forcefully route a specific 
process's network traffic through a proxy WITHOUT changing 
system proxy settings. They do this via:
  - LSP (Winsock Layered Service Provider) injection
  - DLL injection + WinSock API hooking
  - Driver-level packet interception

Detect by:
1. Scan loaded DLLs in OWN PROCESS for unknown WinSock 
   provider DLLs using WSAEnumProtocols():
   - Any provider with dwCatalogEntryId outside the 
     expected range of known Microsoft providers
   - Any provider DLL path outside System32

2. Detect hooks on WinSock functions:
   Check prologues of:
     - ws2_32!connect
     - ws2_32!send
     - ws2_32!recv
     - ws2_32!WSASend
     - ws2_32!WSAConnect
   For JMP/CALL/INT3 redirection (same technique as Module 6, 
   applied to WinSock API layer).

3. Check if process has loaded proxifier's injection DLL:
     - AxGate.dll (Proxifier)
     - ProxyCap*.dll

-----------------------------------------------------------------------
 13E — TOR / ANONYMIZATION NETWORK DETECTION
-----------------------------------------------------------------------
Tor and similar tools create local SOCKS proxies and modify 
routing to anonymize traffic. Detect by:

1. Check for localhost SOCKS proxy on known Tor ports:
     9050  (Tor SOCKS proxy default)
     9150  (Tor Browser SOCKS proxy)
     9051  (Tor control port)
   Use GetExtendedTcpTable() to enumerate listeners.

2. Check for Tor Browser directory artifacts:
     %APPDATA%\Tor Browser\
     %LOCALAPPDATA%\Tor Browser\
     %TEMP%\Tor Browser\
     %DESKTOP%\Tor Browser\

3. Check for Tor process by name and hash:
     tor.exe, torbrowser.exe, firefox.exe 
     (path-qualified: only flag firefox.exe if inside 
     a "Tor Browser" directory path)

4. Check for I2P router:
     i2p.exe, i2prouter.exe, i2p-router.exe
     Port 7656 (I2P SAM bridge), 4444 (I2P HTTP proxy)

-----------------------------------------------------------------------
 13F — RESPONSE TO NETWORK TOOL DETECTION
-----------------------------------------------------------------------
When ANY network-level interception is detected, apply 
the TIERED RESPONSE SYSTEM from Module 9, with additions:

NETWORK-SPECIFIC RESPONSES:
  - Refuse to send any sensitive data 
    (license keys, auth tokens, telemetry) over the 
    network if MITM/proxy is detected
  - If certificate mismatch detected: immediately abort 
    TLS session with a local error — do NOT expose 
    any data to the intercepting proxy
  - If VPN detected: optionally refuse to operate 
    (for geo-restricted or region-locked software)
  - Log detection event to an encrypted local audit trail 
    (AES-256-GCM, key derived from machine fingerprint)
  - Optionally phone home to a protected telemetry endpoint 
    (only if no MITM is present — verified via pinned cert) 
    to report detection event

=======================================================================
 UPDATED PUBLIC API (Add to ProtectionSDK.h)
=======================================================================

// Network-layer protection API additions:

// Returns true if any HTTP intercept tool is detected
bool IsHttpInterceptorPresent();

// Returns true if a MITM certificate is found in cert store
bool IsMitmCertificateInstalled();

// Returns true if system proxy is redirected to a local tool
bool IsSystemProxyHijacked();

// Returns true if a VPN adapter/driver/process is detected
bool IsVpnPresent();

// Returns true if Tor/I2P/anonymization network is active
bool IsAnonymizationNetworkActive();

// Returns true if packet capture driver is loaded
bool IsPacketCaptureDriverLoaded();

// Performs active TLS certificate pinning check against 
// a provided host and expected SHA-256 thumbprint
bool VerifyCertificatePin(
    const wchar_t* host,
    uint16_t       port,
    const uint8_t* expectedSha256Thumbprint,  // 32 bytes
    size_t         thumbprintLen
);

// Combined network safety check (all above)
bool IsNetworkEnvironmentSafe();

=======================================================================
 ADDITIONAL COMPILE-TIME FLAGS
=======================================================================
#define ENABLE_HTTP_INTERCEPT_DETECTION     1
#define ENABLE_CERT_STORE_INSPECTION        1
#define ENABLE_VPN_DETECTION                1
#define ENABLE_PACKET_CAPTURE_DETECTION     1
#define ENABLE_TOR_DETECTION                1
#define ENABLE_CERT_PINNING                 1
#define ENABLE_PROXY_CONFIG_DETECTION       1
#define ENABLE_WINSOCK_HOOK_DETECTION       1
#define ENABLE_ENTERPRISE_PROXY_DETECTION   1  // ZScaler etc.

// Pinned certificate for your backend (set at build time):
#define PINNED_BACKEND_HOST      L"api.yourapp.com"
#define PINNED_BACKEND_PORT      443
#define PINNED_CERT_SHA256       { 0xAB, 0xCD, ... }  // 32 bytes

=======================================================================
 ADDITIONAL DELIVERABLES FOR MODULES 11–13
=======================================================================
1. NetworkProtection.cpp / NetworkProtection.h — 
   full source for all network detection modules
2. CertStoreInspector.cpp — standalone certificate 
   store enumeration and fingerprint checker
3. VpnDetector.cpp — standalone VPN driver/adapter/process detector
4. A NETWORK_TECHNIQUES.md documenting:
   - Every HTTP intercept tool detected and HOW it is detected
   - Every VPN detection vector with registry keys used
   - Certificate store inspection methodology
   - How to extend the fingerprint lists for new tools
5. A BYPASS_ANALYSIS.md documenting known bypass techniques 
   and this SDK's countermeasures against each

=======================================================================
=======================================================================
 TECHNICAL REQUIREMENTS
=======================================================================
- Language: C/C++ (C++17 or later)
- Compiler: MSVC or Clang/LLVM with LTO enabled
- Target: Windows 10/11, x86 and x64
- No external runtime dependencies 
  (statically link or resolve everything dynamically)
- All NT functions called via direct syscall stubs 
  (Halo's Gate / Hell's Gate syscall resolution)
- Provide a clean API header: 
    bool ProtectionInit();        // run all checks
    bool IsEnvironmentSafe();     // aggregate result
    void RegisterTripwire(void(*callback)(int reason));
- Each module must be individually toggleable via 
  compile-time flags (#define ENABLE_ANTIDEBUG, 
  #define ENABLE_ANTIVM, etc.)
- Write unit tests for each detection module using 
  a controlled environment (e.g., detect VirtualBox 
  correctly when run inside it)

=======================================================================
 DELIVERABLES
=======================================================================
1. Full source code for all 10 modules
2. A master ProtectionSDK.h public API header
3. A demo host application that integrates the SDK 
   and reports which checks triggered
4. A CMakeLists.txt or MSVC solution file
5. A TECHNIQUES.md documenting every detection method 
   implemented, the Windows API / kernel structure used, 
   and known bypass methods for each
6. A TESTING.md describing how to validate each module 
   in a controlled lab environment

=======================================================================
 ETHICAL DISCLAIMER TO INCLUDE IN CODE
=======================================================================
All protection techniques implemented in this SDK are for 
LEGITIMATE SOFTWARE PROTECTION purposes only: protecting 
intellectual property, preventing unauthorized reverse 
engineering of licensed software, and hardening applications 
against cracking. This SDK must not be used to protect malware, 
ransomware, or any software intended to cause harm. The developer 
is responsible for compliance with all applicable laws.
=======================================================================
