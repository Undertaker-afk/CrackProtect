#pragma once

namespace IronLock::Modules::AntiDebug {

bool CheckKernelDebugger();
bool CheckSharedUserData();
bool CheckSystemKernelDebuggerInformation();

} // namespace IronLock::Modules::AntiDebug
