#pragma once

#include <string>
#include <vector>

namespace IronLock::Core {

enum class ResponseTier {
    NONE = 0,
    MONITOR,
    SUSPICIOUS,
    HOSTILE
};

struct Evidence {
    std::string check;
    bool suspicious;
    double score;
    double confidence;
    std::string reason;
};

struct Policy {
    std::string name;
    double suspiciousThreshold;
    double hostileThreshold;
    double accelerateHostileThreshold;
    double deferThreshold;
};

struct EvaluationContext {
    bool highValueTarget{false};
    bool userFacingCriticalPath{false};
};

struct PolicyDecision {
    std::string policy;
    double riskScore;
    double confidence;
    ResponseTier tier;
    bool deferred;
    bool accelerated;
    std::vector<Evidence> evidence;
};

class PolicyEngine {
public:
    static void Initialize(const std::string& policyName = "balanced");
    static const Policy& ActivePolicy();
    static PolicyDecision Evaluate(const std::vector<Evidence>& evidence, const EvaluationContext& context);

private:
    static Policy LoadPolicy(const std::string& policyName);
};

} // namespace IronLock::Core
