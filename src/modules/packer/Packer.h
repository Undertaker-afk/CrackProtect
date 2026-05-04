#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace IronLock::Packer {

struct Range {
    uint32_t start{};
    uint32_t size{};
};

struct SectionDescriptor {
    std::string name;
    uint32_t rva{};
    uint32_t virtualSize{};
    uint32_t rawOffset{};
    uint32_t rawSize{};
    uint32_t characteristics{};
};

struct PEImage {
    std::vector<uint8_t> bytes;
    uint32_t imageBase{};
    uint32_t sectionAlignment{};
    uint32_t fileAlignment{};
    uint32_t checksum{};
    uint32_t importRva{};
    uint32_t importSize{};
    uint32_t relocRva{};
    uint32_t relocSize{};
    uint32_t tlsRva{};
    uint32_t tlsSize{};
    uint32_t resourcesRva{};
    uint32_t resourcesSize{};
    std::vector<SectionDescriptor> sections;
};

struct ProtectedSection {
    std::string name;
    uint32_t rva{};
    uint32_t size{};
    uint32_t keyId{};
    uint32_t flags{};
};

struct PackConfig {
    bool includeRdata{false};
    std::vector<Range> exclusionRanges;
    std::string stubSectionName{".ilstub"};
    std::string reportPath;
    std::string configPath;
};

struct PackReport {
    bool success{false};
    std::vector<std::string> diagnostics;
    std::vector<ProtectedSection> protectedSections;
};

std::optional<PEImage> ParsePEImage(const std::string& inputPath, std::vector<std::string>& diagnostics);
bool WritePEImage(const std::string& outputPath, const PEImage& image, std::vector<std::string>& diagnostics);

std::vector<ProtectedSection> SelectSections(const PEImage& image, const PackConfig& config, std::vector<std::string>& diagnostics);
bool BuildPackedImage(PEImage& image, const PackConfig& config, const std::vector<ProtectedSection>& sections,
                      std::vector<std::string>& diagnostics);

bool RunRuntimeStubLoader(const PEImage& image, const std::vector<ProtectedSection>& sections,
                          std::vector<std::string>& diagnostics);

bool VerifyManifestIntegrity(const std::vector<uint8_t>& manifest, uint32_t expectedMac, std::vector<std::string>& diagnostics);

PackReport PackBinary(const std::string& inputPath, const std::string& outputPath, const PackConfig& config);

}  // namespace IronLock::Packer
