#pragma once
#include <windows.h>

namespace IronLock::Modules::Memory {

bool VerifySectionIntegrity();
bool DetectHooks();
bool DetectIATRedirection();
void ErasePEHeader();
void MangleSizeOfImage();

} // namespace IronLock::Modules::Memory
