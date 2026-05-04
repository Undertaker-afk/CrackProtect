#pragma once

namespace IronLock::Modules::Sandbox {

bool CheckUsername();
bool CheckComputerName();
bool CheckUptime();
bool CheckMouseMovement();
bool CheckDiskSpace();
bool CheckLoadedModules();
bool CheckSleepAcceleration();

bool RunAllSandboxChecks();

} // namespace IronLock::Modules::Sandbox
