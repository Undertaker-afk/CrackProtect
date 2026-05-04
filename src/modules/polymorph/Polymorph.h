#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace IronLock::Modules::Polymorph {

enum class BuildMode {
    Deterministic,
    Release,
};

struct BuildConfig {
    BuildMode mode = BuildMode::Release;
    uint64_t fixedSeed = 0;
    std::string buildId;
};

struct BuildManifest {
    uint64_t seed = 0;
    std::string buildId;
    std::unordered_map<uint8_t, uint8_t> opcodeRemap;
    std::unordered_map<uint8_t, uint8_t> operandEncodingRemap;
    std::vector<size_t> handlerOrder;
    std::vector<uint8_t> cfgStateLayout;
    std::vector<uint8_t> junkTemplateOrder;
    std::array<uint8_t, 32> sectionKey{};
    std::array<uint8_t, 32> bytecodeKey{};
};

class PolymorphEngine {
public:
    static BuildManifest Generate(const BuildConfig& config,
                                  const std::vector<uint8_t>& opcodeIds,
                                  const std::vector<uint8_t>& operandEncodings,
                                  size_t handlerCount,
                                  size_t cfgStateCount,
                                  size_t junkTemplateCount,
                                  const std::string& sectionIdentity,
                                  const std::string& bytecodeIdentity);

private:
    static uint64_t GenerateSeed(BuildMode mode, uint64_t fixedSeed);
    static std::array<uint8_t, 32> DeriveKey(uint64_t buildSeed,
                                             const std::string& artifactIdentity,
                                             const std::string& domainTag);
};

} // namespace IronLock::Modules::Polymorph
