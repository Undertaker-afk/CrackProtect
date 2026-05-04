#include "Polymorph.h"

#include <algorithm>
#include <numeric>
#include <random>

#include "core/Hashing.h"

namespace IronLock::Modules::Polymorph {

namespace {

std::mt19937_64 CreateRng(uint64_t seed, uint64_t salt) {
    std::seed_seq seq{
        static_cast<uint32_t>(seed),
        static_cast<uint32_t>(seed >> 32),
        static_cast<uint32_t>(salt),
        static_cast<uint32_t>(salt >> 32),
    };
    return std::mt19937_64(seq);
}

std::vector<size_t> MakeShuffledIndexes(size_t count, std::mt19937_64& rng) {
    std::vector<size_t> indexes(count);
    std::iota(indexes.begin(), indexes.end(), 0);
    std::shuffle(indexes.begin(), indexes.end(), rng);
    return indexes;
}

std::vector<uint8_t> MakeShuffledValues(size_t count, std::mt19937_64& rng) {
    std::vector<uint8_t> values(count);
    std::iota(values.begin(), values.end(), static_cast<uint8_t>(0));
    std::shuffle(values.begin(), values.end(), rng);
    return values;
}

} // namespace

BuildManifest PolymorphEngine::Generate(const BuildConfig& config,
                                        const std::vector<uint8_t>& opcodeIds,
                                        const std::vector<uint8_t>& operandEncodings,
                                        size_t handlerCount,
                                        size_t cfgStateCount,
                                        size_t junkTemplateCount,
                                        const std::string& sectionIdentity,
                                        const std::string& bytecodeIdentity) {
    BuildManifest manifest;
    manifest.seed = GenerateSeed(config.mode, config.fixedSeed);
    manifest.buildId = config.buildId;

    const uint64_t opcodeSalt = Core::Hashing::HashString64("opcode-remap");
    auto opcodeRng = CreateRng(manifest.seed, opcodeSalt);

    std::vector<uint8_t> shuffledOpcodes = opcodeIds;
    std::shuffle(shuffledOpcodes.begin(), shuffledOpcodes.end(), opcodeRng);
    for (size_t i = 0; i < opcodeIds.size(); ++i) {
        manifest.opcodeRemap[opcodeIds[i]] = shuffledOpcodes[i];
    }

    const uint64_t operandSalt = Core::Hashing::HashString64("operand-remap");
    auto operandRng = CreateRng(manifest.seed, operandSalt);
    std::vector<uint8_t> shuffledOperands = operandEncodings;
    std::shuffle(shuffledOperands.begin(), shuffledOperands.end(), operandRng);
    for (size_t i = 0; i < operandEncodings.size(); ++i) {
        manifest.operandEncodingRemap[operandEncodings[i]] = shuffledOperands[i];
    }

    const uint64_t handlerSalt = Core::Hashing::HashString64("handler-layout");
    auto handlerRng = CreateRng(manifest.seed, handlerSalt);
    manifest.handlerOrder = MakeShuffledIndexes(handlerCount, handlerRng);

    const uint64_t cfgSalt = Core::Hashing::HashString64("cfg-layout");
    auto cfgRng = CreateRng(manifest.seed, cfgSalt);
    manifest.cfgStateLayout = MakeShuffledValues(cfgStateCount, cfgRng);

    const uint64_t junkSalt = Core::Hashing::HashString64("cfg-junk");
    auto junkRng = CreateRng(manifest.seed, junkSalt);
    manifest.junkTemplateOrder = MakeShuffledValues(junkTemplateCount, junkRng);

    manifest.sectionKey = DeriveKey(manifest.seed, sectionIdentity, "section-key");
    manifest.bytecodeKey = DeriveKey(manifest.seed, bytecodeIdentity, "bytecode-key");

    return manifest;
}

uint64_t PolymorphEngine::GenerateSeed(BuildMode mode, uint64_t fixedSeed) {
    if (mode == BuildMode::Deterministic) {
        return fixedSeed;
    }

    std::random_device rd;
    const uint64_t high = static_cast<uint64_t>(rd()) << 32;
    const uint64_t low = static_cast<uint64_t>(rd());
    return high | low;
}

std::array<uint8_t, 32> PolymorphEngine::DeriveKey(uint64_t buildSeed,
                                                   const std::string& artifactIdentity,
                                                   const std::string& domainTag) {
    std::array<uint8_t, 32> out{};

    const uint64_t idHash = Core::Hashing::HashString64(artifactIdentity);
    const uint64_t domainHash = Core::Hashing::HashString64(domainTag);

    for (size_t i = 0; i < out.size(); i += sizeof(uint64_t)) {
        const uint64_t laneInput = buildSeed ^ idHash ^ (domainHash + static_cast<uint64_t>(i));
        uint64_t lane = laneInput;
        lane ^= lane >> 30;
        lane *= 0xbf58476d1ce4e5b9ULL;
        lane ^= lane >> 27;
        lane *= 0x94d049bb133111ebULL;
        lane ^= lane >> 31;

        for (size_t b = 0; b < sizeof(uint64_t); ++b) {
            out[i + b] = static_cast<uint8_t>((lane >> (b * 8)) & 0xFF);
        }
    }

    return out;
}

} // namespace IronLock::Modules::Polymorph
