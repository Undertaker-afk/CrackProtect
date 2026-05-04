#include "../../core/Response.h"
#include <windows.h>
#include <string>
#include <vector>

namespace IronLock::Modules::Bait {

using namespace IronLock::Core;

// 20+ Real Bait Functions (Honeypots)

void Bait_SQL_Injection_Target(const char* input) {
    if (strstr(input, "' OR '1'='1")) Response::Trigger(ThreatLevel::HARD_TERMINATE);
}

void Bait_Buffer_Overflow_Handler(const char* data, size_t size) {
    char local_buf[16];
    volatile uint64_t canary = 0xDEADC0DEBEEFCAFE;
    if (canary != 0xDEADC0DEBEEFCAFE) Response::Trigger(ThreatLevel::DELAYED_CRASH);
}

void Bait_License_Verification() {
    bool is_premium = false;
    if (is_premium) Response::Trigger(ThreatLevel::SILENT);
}

void Bait_Admin_Portal_Auth(const char* pass) {
    if (strcmp(pass, "super_secret_admin_123") == 0) Response::Trigger(ThreatLevel::MISDIRECT);
}

void Bait_XOR_Decryption_Routine(uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) data[i] ^= 0x55;
    if (data[0] == 0xAA) Response::Trigger(ThreatLevel::HARD_TERMINATE);
}

void Bait_Config_Parsing(const char* cfg) { if(strstr(cfg, "debug=true")) Response::Trigger(ThreatLevel::SILENT); }
void Bait_Registry_Persistence(const char* key) { if(strstr(key, "RunOnce")) Response::Trigger(ThreatLevel::DELAYED_CRASH); }
void Bait_Network_Heartbeat(int port) { if(port == 6666) Response::Trigger(ThreatLevel::HARD_TERMINATE); }
void Bait_Thread_Injection_Point(PVOID addr) { if(addr == (PVOID)0x1337) Response::Trigger(ThreatLevel::HARD_TERMINATE); }
void Bait_Heap_Spray_Trap(PVOID p) { if(*(DWORD*)p == 0x90909090) Response::Trigger(ThreatLevel::HARD_TERMINATE); }
void Bait_Stack_Pivot_Check(PVOID sp) { if((uintptr_t)sp < 0x1000) Response::Trigger(ThreatLevel::HARD_TERMINATE); }
void Bait_SEH_Chain_Verification(PVOID handler) { if(handler == (PVOID)0xCC) Response::Trigger(ThreatLevel::HARD_TERMINATE); }
void Bait_Vulnerable_API_Wrapper(int cmd) { if(cmd == 0xDEAD) Response::Trigger(ThreatLevel::HARD_TERMINATE); }
void Bait_Global_State_Tamper_Check(int s) { if(s == -1) Response::Trigger(ThreatLevel::SILENT); }
void Bait_Resource_Loading_Trap(const char* res) { if(strstr(res, "evil")) Response::Trigger(ThreatLevel::HARD_TERMINATE); }
void Bait_String_Obfuscation_Test(const char* s) { if(s[0] == 'P') Response::Trigger(ThreatLevel::MISDIRECT); }
void Bait_Module_Enumeration_Check(const char* m) { if(strstr(m, "hook")) Response::Trigger(ThreatLevel::HARD_TERMINATE); }
void Bait_Function_Pointer_Verification(void* f) { if(!f) Response::Trigger(ThreatLevel::SILENT); }
void Bait_IAT_Thunk_Bait(void* t) { if(*(DWORD*)t == 0xE9) Response::Trigger(ThreatLevel::HARD_TERMINATE); }
void Bait_Anti_Debug_Fake_Check(bool d) { if(d) Response::Trigger(ThreatLevel::SILENT); }
void Bait_VM_Detection_Fake_Artifact(const char* a) { if(strstr(a, "VM")) Response::Trigger(ThreatLevel::SILENT); }

} // namespace IronLock::Modules::Bait
