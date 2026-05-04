#include "PolicyEngine.h"

#include <algorithm>
#include <unordered_map>

namespace IronLock::Core {

static Policy g_policy{"balanced", 0.35, 0.70, 0.55, 0.40};

void PolicyEngine::Initialize(const std::string& policyName) {
    g_policy = LoadPolicy(policyName);
}

const Policy& PolicyEngine::ActivePolicy() {
    return g_policy;
}

Policy PolicyEngine::LoadPolicy(const std::string& policyName) {
    if (policyName == "strict") {
        return Policy{"strict", 0.20, 0.45, 0.35, 0.25};
    }
    if (policyName == "stealth") {
        return Policy{"stealth", 0.45, 0.85, 0.70, 0.65};
    }
    return Policy{"balanced", 0.35, 0.70, 0.55, 0.40};
}

ThreatLevel PolicyEngine::MapThreat(const std::string& check, ResponseTier tier) {
    static const std::unordered_map<std::string, ThreatLevel> hostileMap = {
        {"integrity", ThreatLevel::HARD_TERMINATE},
        {"anti_debug.kernel", ThreatLevel::HARD_TERMINATE},
        {"analysis_tools", ThreatLevel::MISDIRECT},
        {"network", ThreatLevel::DELAYED_CRASH}
    };

    if (tier == ResponseTier::NONE || tier == ResponseTier::MONITOR) return ThreatLevel::SILENT;
    auto it = hostileMap.find(check);
    if (it != hostileMap.end()) return it->second;
    return tier == ResponseTier::HOSTILE ? ThreatLevel::HARD_TERMINATE : ThreatLevel::MISDIRECT;
}

PolicyDecision PolicyEngine::Evaluate(const std::vector<Evidence>& evidence, const EvaluationContext& context) {
    double weightedRisk = 0.0;
    double weightedConfidence = 0.0;
    double weightSum = 0.0;
    const Evidence* topThreat = nullptr;

    for (const auto& item : evidence) {
        const double evidenceWeight = std::clamp(item.confidence, 0.0, 1.0);
        const double signedScore = item.suspicious ? item.score : 0.0;
        weightedRisk += signedScore * evidenceWeight;
        weightedConfidence += item.confidence;
        weightSum += evidenceWeight;
        if (item.suspicious && (!topThreat || item.score > topThreat->score)) topThreat = &item;
    }

    const double riskScore = (weightSum > 0.0) ? (weightedRisk / weightSum) : 1.0; // fail-closed default
    const double confidence = evidence.empty() ? 0.0 : (weightedConfidence / static_cast<double>(evidence.size()));

    bool accelerated = false;
    bool deferred = false;

    ResponseTier tier = ResponseTier::NONE;
    if (riskScore >= g_policy.hostileThreshold) {
        tier = ResponseTier::HOSTILE;
    } else if (riskScore >= g_policy.suspiciousThreshold) {
        tier = ResponseTier::SUSPICIOUS;
    } else if (riskScore > 0.0) {
        tier = ResponseTier::MONITOR;
    }

    if (context.highValueTarget && riskScore >= g_policy.accelerateHostileThreshold) {
        tier = ResponseTier::HOSTILE;
        accelerated = true;
    }

    if (context.userFacingCriticalPath && riskScore < g_policy.deferThreshold && tier != ResponseTier::NONE) {
        deferred = true;
        tier = ResponseTier::MONITOR;
    }

    const std::string driverCheck = topThreat ? topThreat->check : std::string("unknown");
    ThreatLevel mapped = MapThreat(driverCheck, tier);
    return PolicyDecision{g_policy.name, riskScore, confidence, tier, deferred, accelerated, evidence, mapped};
}

} // namespace IronLock::Core
