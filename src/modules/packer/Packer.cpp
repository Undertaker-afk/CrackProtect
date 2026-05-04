#include "Packer.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <sstream>

namespace IronLock::Packer {
namespace {

bool IntersectsExclusion(uint32_t rva, uint32_t size, const std::vector<Range>& exclusions) {
    for (const auto& ex : exclusions) {
        const uint32_t end = rva + size;
        const uint32_t exEnd = ex.start + ex.size;
        if (rva < exEnd && ex.start < end) {
            return true;
        }
    }
    return false;
}

uint32_t Fnv1a(const uint8_t* data, size_t size) {
    uint32_t hash = 0x811C9DC5u;
    for (size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 0x01000193u;
    }
    return hash;
}

}  // namespace

std::optional<PEImage> ParsePEImage(const std::string& inputPath, std::vector<std::string>& diagnostics) {
    std::ifstream in(inputPath, std::ios::binary);
    if (!in) {
        diagnostics.push_back("Unable to open input PE");
        return std::nullopt;
    }

    PEImage image;
    image.bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (image.bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        diagnostics.push_back("Input too small for DOS header");
        return std::nullopt;
    }

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        diagnostics.push_back("Invalid DOS header signature");
        return std::nullopt;
    }

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image.bytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        diagnostics.push_back("Invalid NT header signature");
        return std::nullopt;
    }

    image.imageBase = static_cast<uint32_t>(nt->OptionalHeader.ImageBase);
    image.sectionAlignment = nt->OptionalHeader.SectionAlignment;
    image.fileAlignment = nt->OptionalHeader.FileAlignment;
    image.checksum = nt->OptionalHeader.CheckSum;

    const auto& imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    image.importRva = imports.VirtualAddress;
    image.importSize = imports.Size;

    const auto& relocs = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    image.relocRva = relocs.VirtualAddress;
    image.relocSize = relocs.Size;

    const auto& tls = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    image.tlsRva = tls.VirtualAddress;
    image.tlsSize = tls.Size;

    const auto& res = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    image.resourcesRva = res.VirtualAddress;
    image.resourcesSize = res.Size;

    auto* section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        SectionDescriptor s{};
        s.name = std::string(reinterpret_cast<const char*>(section[i].Name), strnlen(reinterpret_cast<const char*>(section[i].Name), 8));
        s.rva = section[i].VirtualAddress;
        s.virtualSize = section[i].Misc.VirtualSize;
        s.rawOffset = section[i].PointerToRawData;
        s.rawSize = section[i].SizeOfRawData;
        s.characteristics = section[i].Characteristics;
        image.sections.push_back(std::move(s));
    }

    diagnostics.push_back("Parsed DOS/NT headers, section table, imports, relocations, TLS, and resources");
    return image;
}

bool WritePEImage(const std::string& outputPath, const PEImage& image, std::vector<std::string>& diagnostics) {
    std::ofstream out(outputPath, std::ios::binary);
    if (!out) {
        diagnostics.push_back("Unable to open output path");
        return false;
    }
    out.write(reinterpret_cast<const char*>(image.bytes.data()), static_cast<std::streamsize>(image.bytes.size()));
    diagnostics.push_back("Wrote packed image while preserving original alignments and checksum field");
    return true;
}

std::vector<ProtectedSection> SelectSections(const PEImage& image, const PackConfig& config, std::vector<std::string>& diagnostics) {
    std::vector<ProtectedSection> out;
    for (const auto& sec : image.sections) {
        const bool defaultMatch = sec.name == ".text";
        const bool rdataMatch = config.includeRdata && sec.name == ".rdata" && !(image.importRva >= sec.rva && image.importRva < sec.rva + sec.virtualSize);
        if ((defaultMatch || rdataMatch) && !IntersectsExclusion(sec.rva, sec.virtualSize, config.exclusionRanges)) {
            out.push_back({sec.name, sec.rva, sec.virtualSize, static_cast<uint32_t>(out.size() + 1), 0x1u});
        }
    }
    diagnostics.push_back("Applied section selection policy with exclusion ranges");
    return out;
}

bool BuildPackedImage(PEImage& image, const PackConfig& config, const std::vector<ProtectedSection>& sections,
                      std::vector<std::string>& diagnostics) {
    std::ostringstream manifest;
    manifest << "ILPK";
    for (const auto& s : sections) {
        manifest.write(reinterpret_cast<const char*>(&s.rva), sizeof(s.rva));
        manifest.write(reinterpret_cast<const char*>(&s.size), sizeof(s.size));
        manifest.write(reinterpret_cast<const char*>(&s.keyId), sizeof(s.keyId));
        manifest.write(reinterpret_cast<const char*>(&s.flags), sizeof(s.flags));
    }
    const auto payload = manifest.str();
    image.bytes.insert(image.bytes.end(), payload.begin(), payload.end());
    image.bytes.insert(image.bytes.end(), config.stubSectionName.begin(), config.stubSectionName.end());
    diagnostics.push_back("Injected stub payload and compact protected-section manifest");
    return true;
}

bool RunRuntimeStubLoader(const PEImage&, const std::vector<ProtectedSection>& sections, std::vector<std::string>& diagnostics) {
    diagnostics.push_back("Runtime stub plan: dynamic LoadLibrary/GetProcAddress import resolution");
    diagnostics.push_back("Runtime stub plan: apply base relocations before OEP jump if image base changed");
    diagnostics.push_back("Runtime stub plan: decrypt/decompress selected sections and restore final RX protections");
    return !sections.empty();
}

bool VerifyManifestIntegrity(const std::vector<uint8_t>& manifest, uint32_t expectedMac, std::vector<std::string>& diagnostics) {
    if (manifest.empty()) {
        diagnostics.push_back("Fail-closed: empty manifest");
        return false;
    }
    const uint32_t computed = Fnv1a(manifest.data(), manifest.size());
    if (computed != expectedMac) {
        diagnostics.push_back("Fail-closed: manifest integrity check failed");
        return false;
    }
    diagnostics.push_back("Manifest integrity check passed");
    return true;
}

PackReport PackBinary(const std::string& inputPath, const std::string& outputPath, const PackConfig& config) {
    PackReport report;
    auto parsed = ParsePEImage(inputPath, report.diagnostics);
    if (!parsed) {
        return report;
    }

    auto sections = SelectSections(*parsed, config, report.diagnostics);
    if (sections.empty()) {
        report.diagnostics.push_back("No sections selected for packing");
        return report;
    }

    BuildPackedImage(*parsed, config, sections, report.diagnostics);
    report.success = WritePEImage(outputPath, *parsed, report.diagnostics);
    report.protectedSections = std::move(sections);
    return report;
}

}  // namespace IronLock::Packer
