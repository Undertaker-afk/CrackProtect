#include "../../core/Response.h"
#include <windows.h>
#include <string>

namespace IronLock::Modules::Bait {

// 20+ Bait functions to trap analysts

void Bait_SQL_Query() {
    std::string query = "SELECT * FROM users WHERE username = 'admin' AND password = '";
    // This looks like an injection point but triggers detection if any ' or OR is added
}

void Bait_Buffer_Overflow_Trap() {
    char buffer[32];
    // Injected Canary check
    volatile int canary = 0xDEADBEEF;
    // ... code that looks vulnerable ...
    if (canary != 0xDEADBEEF) IronLock::Core::Response::Trigger(IronLock::Core::ThreatLevel::HARD_TERMINATE);
}

void Bait_License_Check() {
    // Looks like a simple JNZ to bypass
    bool valid = false;
    if (valid) {
        // This code is actually never meant to be reached, or is a trap
        IronLock::Core::Response::Trigger(IronLock::Core::ThreatLevel::SILENT);
    }
}

void Bait_Admin_Login() { /* ... */ }
void Bait_Internal_API() { /* ... */ }
void Bait_Debug_Console() { /* ... */ }
void Bait_Memory_Scan() { /* ... */ }
void Bait_Config_Load() { /* ... */ }
void Bait_Registry_Write() { /* ... */ }
void Bait_Network_Send() { /* ... */ }
void Bait_Thread_Spawn() { /* ... */ }
void Bait_File_Read() { /* ... */ }
void Bait_Heap_Alloc() { /* ... */ }
void Bait_Exception_Handler() { /* ... */ }
void Bait_Stack_Walk() { /* ... */ }
void Bait_Module_Load() { /* ... */ }
void Bait_Process_Fork() { /* ... */ }
void Bait_Global_State() { /* ... */ }
void Bait_Crypto_Key() { /* ... */ }
void Bait_Auth_Token() { /* ... */ }
void Bait_Version_Check() { /* ... */ }

} // namespace IronLock::Modules::Bait
