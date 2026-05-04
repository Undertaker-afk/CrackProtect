#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace IronLock::Core {

enum class ProfileMode : uint8_t {
    DEFAULT = 0,
    DETERMINISTIC,
    HARDENED
};

struct ProfileConfig {
    uint32_t schemaVersion{1};
    std::vector<std::string> enabledModules{"anti_debug", "integrity", "sandbox"};
    uint8_t aggressiveness{35};
    std::string responsePolicy{"balanced"};
    std::string virtualizationScope{"sensitive"};
    ProfileMode mode{ProfileMode::DEFAULT};
    std::array<uint64_t, 4> fixedSeeds{0xA5311E4Du, 0x9BC1022Fu, 0x74CC55A1u, 0x11EE0D99u};

    static ProfileConfig SafeDefaults();
};

class ProfileLoader {
public:
    static std::optional<ProfileConfig> LoadFromPath(const std::string& path, std::string* error = nullptr);
    static ProfileConfig MigrateToCurrent(const ProfileConfig& input, uint32_t* migratedFrom = nullptr);
    static bool IsModuleEnabled(const ProfileConfig& profile, const std::string& module);
};

} // namespace IronLock::Core
