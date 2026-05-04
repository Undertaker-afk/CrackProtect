#pragma once
#include <vector>
#include <string>

namespace IronLock::Modules::Tools {

bool CheckProcessNames();
bool CheckWindowTitles();
bool CheckLoadedModules();

bool RunAllToolChecks();

} // namespace IronLock::Modules::Tools
