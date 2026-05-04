#pragma once
#include <windows.h>

namespace IronLock::Modules::AntiDebug {

bool CheckPEB();
bool CheckRemoteDebugger();
bool CheckProcessDebugPort();
bool CheckProcessDebugFlags();
bool CheckProcessDebugObject();
bool CheckInvalidHandle();
bool CheckHeapFlags();
bool CheckHardwareBreakpoints();
bool CheckSoftwareBreakpoints();
bool CheckTimingDelta();
bool CheckOutputDebugString();
bool CheckGuardPage();
bool CheckTrapFlag();
bool CheckParentProcess();
bool CheckSeDebugPrivilege();
bool CheckThreadHideFromDebugger();
bool CheckDebugApiHooks();

// Aggregate check
bool RunUserModeChecks();

} // namespace IronLock::Modules::AntiDebug
