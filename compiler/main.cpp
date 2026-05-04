#include <windows.h>

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "../src/modules/packer/Packer.h"

namespace {

struct ProtectedRegion {
    std::string name;
    uint32_t rva{};
    uint32_t size{};
};

struct RelocationPatch {
    std::string routine;
    uint32_t callsiteRva{};
    uint32_t vmStubRva{};
};

struct BuildManifest {
    uint32_t version{1};
    uint32_t integrityPlaceholder{0xAAAAAAAA};
    uint32_t integrityHash{};
    std::vector<ProtectedRegion> regions;
    std::vector<RelocationPatch> patches;
    std::unordered_map<std::string, std::string> runtimeConfig;
};

std::string Trim(const std::string& value) {
    size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }
    size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(start, end - start);
}

std::optional<BuildManifest> LoadManifestTemplate(const std::filesystem::path& path) {
    BuildManifest manifest;
    std::ifstream in(path);
    if (!in) {
        return std::nullopt;
    }

    std::string line;
    while (std::getline(in, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }

        auto eqPos = line.find('=');
        if (eqPos == std::string::npos) {
            continue;
        }

        std::string key = Trim(line.substr(0, eqPos));
        std::string value = Trim(line.substr(eqPos + 1));

        if (key == "version") {
            manifest.version = static_cast<uint32_t>(std::stoul(value));
        } else if (key == "integrity.placeholder") {
            manifest.integrityPlaceholder = static_cast<uint32_t>(std::stoul(value, nullptr, 0));
        } else if (key.rfind("runtime.", 0) == 0) {
            manifest.runtimeConfig.emplace(key.substr(8), value);
        } else if (key.rfind("region.", 0) == 0) {
            // format: region.<name>=<rva>,<size>
            auto comma = value.find(',');
            if (comma == std::string::npos) {
                continue;
            }
            ProtectedRegion region;
            region.name = key.substr(7);
            region.rva = static_cast<uint32_t>(std::stoul(Trim(value.substr(0, comma)), nullptr, 0));
            region.size = static_cast<uint32_t>(std::stoul(Trim(value.substr(comma + 1)), nullptr, 0));
            manifest.regions.push_back(region);
        }
    }

    return manifest;
}

uint32_t ComputeTextHash(const std::vector<char>& fileBuffer) {
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileBuffer.data());
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(fileBuffer.data() + dos->e_lfanew);
    auto* section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp(reinterpret_cast<const char*>(section[i].Name), ".text") == 0) {
            uint32_t hash = 0x811C9DC5;
            for (DWORD j = 0; j < section[i].Misc.VirtualSize; ++j) {
                hash ^= static_cast<uint8_t>(fileBuffer[section[i].PointerToRawData + j]);
                hash *= 0x01000193;
            }
            return hash;
        }
    }

    return 0;
}

void ApplyManifestPatches(const std::string& binaryPath, BuildManifest& manifest) {
    std::ifstream input(binaryPath, std::ios::binary);
    if (!input) {
        std::cerr << "[!] IronLock: Unable to open binary for patching: " << binaryPath << "\n";
        return;
    }

    std::vector<char> buffer((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    input.close();

    manifest.integrityHash = ComputeTextHash(buffer);

    std::fstream patchFile(binaryPath, std::ios::binary | std::ios::in | std::ios::out);
    if (!patchFile) {
        std::cerr << "[!] IronLock: Unable to re-open binary for write: " << binaryPath << "\n";
        return;
    }

    // Structured, manifest-driven placeholder patching.
    for (size_t i = 0; i + sizeof(uint32_t) <= buffer.size(); ++i) {
        auto* ptr = reinterpret_cast<uint32_t*>(buffer.data() + i);
        if (*ptr == manifest.integrityPlaceholder) {
            patchFile.seekp(static_cast<std::streamoff>(i));
            patchFile.write(reinterpret_cast<const char*>(&manifest.integrityHash), sizeof(manifest.integrityHash));
        }
    }

    // Patch relocation records. Each record describes a callsite and its VM stub target.
    for (const auto& patch : manifest.patches) {
        // In x86/x64 near call (E8), displacement is relative to the next instruction.
        // Assume manifest callsite points to the displacement field.
        if (patch.callsiteRva + sizeof(uint32_t) > buffer.size()) {
            continue;
        }

        int32_t rel = static_cast<int32_t>(patch.vmStubRva) - static_cast<int32_t>(patch.callsiteRva + 4);
        patchFile.seekp(static_cast<std::streamoff>(patch.callsiteRva));
        patchFile.write(reinterpret_cast<const char*>(&rel), sizeof(rel));
    }

    patchFile.close();
}

void WritePostLinkManifest(const std::filesystem::path& outPath, const BuildManifest& manifest) {
    std::ofstream out(outPath);
    out << "version=" << manifest.version << "\n";
    out << "integrity.placeholder=0x" << std::hex << manifest.integrityPlaceholder << "\n";
    out << "integrity.hash=0x" << std::hex << manifest.integrityHash << "\n";
    out << std::dec;

    for (const auto& region : manifest.regions) {
        out << "region." << region.name << "=0x" << std::hex << region.rva << ",0x" << region.size << "\n";
    }
    out << std::dec;

    for (const auto& patch : manifest.patches) {
        out << "patch." << patch.routine << "=0x" << std::hex << patch.callsiteRva << ",0x" << patch.vmStubRva << "\n";
    }
    out << std::dec;

    for (const auto& [k, v] : manifest.runtimeConfig) {
        out << "runtime." << k << "=" << v << "\n";
    }
}



struct PackOptions {
    bool enabled{false};
    std::string inputPath;
    std::string outputPath;
    std::string configPath;
    std::string reportPath{"pack-report.json"};
};

PackOptions ParsePackOptions(int argc, char* argv[]) {
    PackOptions options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--pack" && i + 2 < argc) {
            options.enabled = true;
            options.inputPath = argv[++i];
            options.outputPath = argv[++i];
        } else if (arg.rfind("--pack-config=", 0) == 0) {
            options.configPath = arg.substr(14);
        } else if (arg.rfind("--pack-report=", 0) == 0) {
            options.reportPath = arg.substr(14);
        }
    }
    return options;
}

IronLock::Packer::PackConfig LoadPackConfig(const PackOptions& options) {
    IronLock::Packer::PackConfig cfg;
    cfg.configPath = options.configPath;
    cfg.reportPath = options.reportPath;
    if (options.configPath.empty()) {
        return cfg;
    }

    std::ifstream in(options.configPath);
    std::string line;
    while (std::getline(in, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        auto key = Trim(line.substr(0, eq));
        auto value = Trim(line.substr(eq + 1));
        if (key == "include_rdata") cfg.includeRdata = (value == "1" || value == "true");
        if (key == "exclude") {
            auto comma = value.find(',');
            if (comma != std::string::npos) {
                IronLock::Packer::Range r;
                r.start = static_cast<uint32_t>(std::stoul(value.substr(0, comma), nullptr, 0));
                r.size = static_cast<uint32_t>(std::stoul(value.substr(comma + 1), nullptr, 0));
                cfg.exclusionRanges.push_back(r);
            }
        }
    }
    return cfg;
}

void WritePackReport(const std::string& path, const IronLock::Packer::PackReport& report) {
    std::ofstream out(path);
    out << "{\n  \"success\": " << (report.success ? "true" : "false") << ",\n";
    out << "  \"diagnostics\": [";
    for (size_t i = 0; i < report.diagnostics.size(); ++i) {
        if (i) out << ", ";
        out << "\"" << report.diagnostics[i] << "\"";
    }
    out << "],\n  \"protectedSections\": [\n";
    for (size_t i = 0; i < report.protectedSections.size(); ++i) {
        const auto& s = report.protectedSections[i];
        out << "    {\"name\":\"" << s.name << "\",\"rva\":" << s.rva
            << ",\"size\":" << s.size << ",\"keyId\":" << s.keyId << ",\"flags\":" << s.flags << "}";
        if (i + 1 < report.protectedSections.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n}\n";
}
}  // namespace

int main(int argc, char* argv[]) {
    const auto packOptions = ParsePackOptions(argc, argv);
    if (packOptions.enabled) {
        auto config = LoadPackConfig(packOptions);
        const auto report = IronLock::Packer::PackBinary(packOptions.inputPath, packOptions.outputPath, config);
        WritePackReport(packOptions.reportPath, report);
        std::cout << (report.success ? "[+]" : "[!]") << " IronLock: pack pipeline complete. report=" << packOptions.reportPath << "\n";
        return report.success ? 0 : 1;
    }

    std::stringstream cmd;
    cmd << "cl.exe";

    std::string outExe = "a.exe";
    std::filesystem::path manifestTemplate = "ironlock.manifest";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.find("/Fe") == 0) {
            outExe = arg.substr(3);
        } else if (arg.rfind("/ILMANIFEST:", 0) == 0) {
            manifestTemplate = arg.substr(std::string("/ILMANIFEST:").size());
            continue;
        }
        cmd << ' ' << arg;
    }

    cmd << " /nologo /O2 /MT /I../include /link /LIBPATH:../build IronLock.lib Advapi32.lib User32.lib Iphlpapi.lib Shell32.lib Crypt32.lib";

    std::cout << "[*] IronLock Compiler: Executing MSVC..." << std::endl;
    int res = system(cmd.str().c_str());

    if (res != 0) {
        return res;
    }

    BuildManifest manifest;
    if (auto loaded = LoadManifestTemplate(manifestTemplate)) {
        manifest = *loaded;
    } else {
        manifest.runtimeConfig["vm_mode"] = "default";
        manifest.runtimeConfig["integrity_enforced"] = "true";
    }

    ApplyManifestPatches(outExe, manifest);
    WritePostLinkManifest(outExe + ".ironlock.manifest", manifest);

    std::cout << "[+] IronLock: Build completed, patched, and manifest emitted." << std::endl;
    return 0;
}
