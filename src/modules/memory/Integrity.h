#pragma once
#include <windows.h>

namespace IronLock::Modules::Memory {

bool VerifySectionIntegrity();
bool DetectHooks();
void ErasePEHeader();
void MangleSizeOfImage();
bool DetectProcessHollowing();
bool DetectInjectedThreads();
void PatchAntiAttach();

} // namespace IronLock::Modules::Memory
