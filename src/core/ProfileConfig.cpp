#include "ProfileConfig.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <unordered_map>

namespace IronLock::Core {
namespace {
constexpr uint32_t kCurrentSchemaVersion = 2;

std::string Trim(std::string v) {
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.front()))) v.erase(v.begin());
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back()))) v.pop_back();
    return v;
}

std::string StripQuotes(std::string v) {
    v = Trim(v);
    if (v.size() >= 2 && ((v.front() == '"' && v.back() == '"') || (v.front() == '\'' && v.back() == '\''))) {
        return v.substr(1, v.size() - 2);
    }
    return v;
}

std::vector<std::string> ParseList(const std::string& text) {
    std::string s = Trim(text);
    if (!s.empty() && (s.front() == '[' || s.front() == '{')) s.erase(s.begin());
    if (!s.empty() && (s.back() == ']' || s.back() == '}')) s.pop_back();

    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        item = StripQuotes(Trim(item));
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

bool ParseBool(const std::string& value) {
    std::string v = value;
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

ProfileMode ParseMode(const std::string& value) {
    std::string v = value;
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (v == "deterministic") return ProfileMode::DETERMINISTIC;
    if (v == "hardened") return ProfileMode::HARDENED;
    return ProfileMode::DEFAULT;
}
} // namespace

ProfileConfig ProfileConfig::SafeDefaults() {
    return ProfileConfig{};
}

std::optional<ProfileConfig> ProfileLoader::LoadFromPath(const std::string& path, std::string* error) {
    std::ifstream in(path);
    if (!in) {
        if (error) *error = "Could not open profile";
        return std::nullopt;
    }

    ProfileConfig cfg = ProfileConfig::SafeDefaults();
    std::unordered_map<std::string, std::string> kv;

    std::string line;
    while (std::getline(in, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#' || line.rfind("//", 0) == 0) continue;

        std::string key;
        std::string value;
        size_t pos = line.find('=');
        if (pos == std::string::npos) pos = line.find(':');
        if (pos == std::string::npos) continue;

        key = Trim(line.substr(0, pos));
        value = Trim(line.substr(pos + 1));

        if (!key.empty() && (key.front() == '"' || key.front() == '\'')) key = StripQuotes(key);
        kv[key] = value;
    }

    if (kv.count("schema_version")) cfg.schemaVersion = static_cast<uint32_t>(std::stoul(StripQuotes(kv["schema_version"])));
    if (kv.count("profile.schema_version")) cfg.schemaVersion = static_cast<uint32_t>(std::stoul(StripQuotes(kv["profile.schema_version"])));
    if (kv.count("aggressiveness")) cfg.aggressiveness = static_cast<uint8_t>(std::min(100UL, std::stoul(StripQuotes(kv["aggressiveness"]))));
    if (kv.count("profile.aggressiveness")) cfg.aggressiveness = static_cast<uint8_t>(std::min(100UL, std::stoul(StripQuotes(kv["profile.aggressiveness"]))));
    if (kv.count("response_policy")) cfg.responsePolicy = StripQuotes(kv["response_policy"]);
    if (kv.count("profile.response_policy")) cfg.responsePolicy = StripQuotes(kv["profile.response_policy"]);
    if (kv.count("virtualization_scope")) cfg.virtualizationScope = StripQuotes(kv["virtualization_scope"]);
    if (kv.count("profile.virtualization_scope")) cfg.virtualizationScope = StripQuotes(kv["profile.virtualization_scope"]);
    if (kv.count("mode")) cfg.mode = ParseMode(StripQuotes(kv["mode"]));
    if (kv.count("profile.mode")) cfg.mode = ParseMode(StripQuotes(kv["profile.mode"]));
    if (kv.count("enabled_modules")) cfg.enabledModules = ParseList(kv["enabled_modules"]);
    if (kv.count("profile.enabled_modules")) cfg.enabledModules = ParseList(kv["profile.enabled_modules"]);
    if (kv.count("telemetry_mode")) cfg.telemetryMode = ParseBool(StripQuotes(kv["telemetry_mode"]));
    if (kv.count("profile.telemetry_mode")) cfg.telemetryMode = ParseBool(StripQuotes(kv["profile.telemetry_mode"]));

    return MigrateToCurrent(cfg);
}

ProfileConfig ProfileLoader::MigrateToCurrent(const ProfileConfig& input, uint32_t* migratedFrom) {
    ProfileConfig out = input;
    if (input.schemaVersion < kCurrentSchemaVersion) {
        if (migratedFrom) *migratedFrom = input.schemaVersion;
        out.schemaVersion = kCurrentSchemaVersion;
        if (out.responsePolicy == "strict") {
            out.responsePolicy = "balanced";
            out.aggressiveness = std::min<uint8_t>(out.aggressiveness, 45);
        }
    }
    return out;
}

bool ProfileLoader::IsModuleEnabled(const ProfileConfig& profile, const std::string& module) {
    return std::find(profile.enabledModules.begin(), profile.enabledModules.end(), module) != profile.enabledModules.end();
}

} // namespace IronLock::Core
