#pragma once

#include <string>
#include <vector>

namespace IronLock::Modules::AntiAnalysis {

struct Signal {
    std::string check;
    bool suspicious;
    double score;
    double confidence;
    std::string reason;
};

struct Result {
    bool suspicious;
    double aggregateScore;
    std::vector<Signal> signals;
};

void ConfigureTelemetry(bool enabled);
Result RunAllChecks();

} // namespace IronLock::Modules::AntiAnalysis
