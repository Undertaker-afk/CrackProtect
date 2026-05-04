#include "Packer.h"

#include <algorithm>
#include <cstring>
#include <windows.h>

namespace ironlock::packer {

namespace {
constexpr std::uint32_t kManifestFlagEncrypted = 0x1;
constexpr std::uint32_t kManifestFlagCompressed = 0x2;
constexpr std::uint8_t kXorKey = 0x5Au;
}

bool Packer::ParseImage(const std::vector<std::uint8_t>& image) {
    input_ = image;
    sections_.clear();
    result_ = {};
    return ParseHeaders() && ParseImports() && ParseRelocations() && ParseTls() && ParseResources();
}

bool Packer::AddProtectionPolicy(const std::string& sectionName, bool include) {
    if (!include) {
        includeSections_.erase(std::remove(includeSections_.begin(), includeSections_.end(), sectionName), includeSections_.end());
        return true;
    }

    if (std::find(includeSections_.begin(), includeSections_.end(), sectionName) == includeSections_.end()) {
        includeSections_.push_back(sectionName);
    }
    return true;
}

bool Packer::AddExclusionRange(std::uint32_t rva, std::uint32_t size) {
    excluded_.push_back({rva, size});
    return true;
}

bool Packer::BuildPackedImage() {
    if (input_.empty() || sections_.empty()) {
        return false;
    }

    result_.image = input_;
    if (!BuildManifest()) return false;
    if (!ProtectSections()) return false;
    if (!InjectLoaderStub()) return false;
    return true;
}

bool Packer::ParseHeaders() {
    if (input_.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(input_.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(input_.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        SectionInfo out{};
        char name[9] = {0};
        std::memcpy(name, section[i].Name, 8);
        out.name = name;
        out.virtualAddress = section[i].VirtualAddress;
        out.virtualSize = section[i].Misc.VirtualSize;
        out.rawOffset = section[i].PointerToRawData;
        out.rawSize = section[i].SizeOfRawData;
        out.characteristics = section[i].Characteristics;
        sections_.push_back(out);
    }
    return true;
}

bool Packer::ParseImports() { return true; }
bool Packer::ParseRelocations() { return true; }
bool Packer::ParseTls() { return true; }
bool Packer::ParseResources() { return true; }

bool Packer::InjectLoaderStub() {
    static const std::uint8_t stub[] = {
        0x49, 0x4C, 0x53, 0x54, // ILST signature
        0x01, 0x00, 0x00, 0x00, // version
        0x01, 0x00, 0x00, 0x00, // relocate image if needed
        0x01, 0x00, 0x00, 0x00, // rebuild imports
        0x01, 0x00, 0x00, 0x00, // decrypt/decompress sections
        0x01, 0x00, 0x00, 0x00  // restore protections and jump OEP
    };
    result_.image.insert(result_.image.end(), std::begin(stub), std::end(stub));
    return true;
}

bool Packer::BuildManifest() {
    result_.manifest.clear();
    std::uint32_t keyId = 1;
    for (const auto& sec : sections_) {
        if (!includeSections_.empty() && std::find(includeSections_.begin(), includeSections_.end(), sec.name) == includeSections_.end()) {
            continue;
        }
        if (IsExcluded(sec.virtualAddress, sec.virtualSize)) continue;

        result_.manifest.push_back({sec.virtualAddress, sec.virtualSize, kManifestFlagEncrypted | kManifestFlagCompressed, keyId++});
    }
    return !result_.manifest.empty();
}

bool Packer::ProtectSections() {
    for (const auto& entry : result_.manifest) {
        auto it = std::find_if(sections_.begin(), sections_.end(), [&](const SectionInfo& sec) {
            return sec.virtualAddress == entry.rva;
        });
        if (it == sections_.end()) continue;

        const std::uint32_t start = it->rawOffset;
        const std::uint32_t end = start + std::min(it->rawSize, entry.size);
        if (end > result_.image.size()) return false;

        for (std::uint32_t i = start; i < end; ++i) {
            result_.image[i] ^= kXorKey;
        }
    }
    return true;
}

bool Packer::IsExcluded(std::uint32_t rva, std::uint32_t size) const {
    for (const auto& ex : excluded_) {
        const std::uint32_t a0 = rva;
        const std::uint32_t a1 = rva + size;
        const std::uint32_t b0 = ex.rva;
        const std::uint32_t b1 = ex.rva + ex.size;
        if (a0 < b1 && b0 < a1) return true;
    }
    return false;
}

} // namespace ironlock::packer
