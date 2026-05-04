#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ironlock::packer {

struct Range {
    std::uint32_t rva;
    std::uint32_t size;
};

struct SectionInfo {
    std::string name;
    std::uint32_t virtualAddress;
    std::uint32_t virtualSize;
    std::uint32_t rawOffset;
    std::uint32_t rawSize;
    std::uint32_t characteristics;
};

struct PackerMetadata {
    std::uint32_t rva;
    std::uint32_t size;
    std::uint32_t flags;
    std::uint32_t keyId;
};

struct PackerResult {
    std::vector<std::uint8_t> image;
    std::vector<PackerMetadata> manifest;
};

class Packer {
public:
    Packer() = default;

    bool ParseImage(const std::vector<std::uint8_t>& image);
    bool AddProtectionPolicy(const std::string& sectionName, bool include);
    bool AddExclusionRange(std::uint32_t rva, std::uint32_t size);
    bool BuildPackedImage();

    const std::vector<SectionInfo>& Sections() const { return sections_; }
    const PackerResult& Result() const { return result_; }

private:
    bool ParseHeaders();
    bool ParseImports();
    bool ParseRelocations();
    bool ParseTls();
    bool ParseResources();

    bool InjectLoaderStub();
    bool BuildManifest();
    bool ProtectSections();

    bool IsExcluded(std::uint32_t rva, std::uint32_t size) const;

    std::vector<std::uint8_t> input_;
    std::vector<SectionInfo> sections_;
    std::vector<std::string> includeSections_;
    std::vector<Range> excluded_;
    PackerResult result_;
};

} // namespace ironlock::packer
