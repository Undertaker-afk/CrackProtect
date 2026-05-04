#pragma once

// IronLock Function Name Randomization Macros
// In a protected build, these macros are redefined by the Compiler Engine
// to map to random strings.

#ifdef IRONLOCK_BUILD_PROTECTED
// These would be generated per-build by the Compiler Engine
#define IL_DetectDebugger  random_func_39281
#define IL_CheckVM         random_func_91823
#define IL_IsSafe          random_func_44512
#else
// Default names for development
#define IL_DetectDebugger  IL_DetectDebugger_Internal
#define IL_CheckVM         IL_CheckVM_Internal
#define IL_IsSafe          IL_IsSafe_Internal
#endif
