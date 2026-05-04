#pragma once

namespace IronLock::Modules::AntiVM {

bool CheckCPUID();
bool CheckHypervisorBit();
bool CheckSMBIOS();
bool CheckRegistryKeys();
bool CheckDrivers();
bool CheckVMwareBackdoor();
bool CheckVBoxArtifacts();
bool CheckHyperV();

bool RunAllVMChecks();

} // namespace IronLock::Modules::AntiVM
