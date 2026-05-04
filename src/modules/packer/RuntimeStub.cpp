#include "RuntimeStub.h"

namespace ironlock::packer {

static std::uint32_t Crc32(const std::vector<std::uint8_t>& data) {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (auto b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            crc = (crc >> 1) ^ (0xEDB88320u & static_cast<std::uint32_t>(-(crc & 1)));
        }
    }
    return ~crc;
}

bool RuntimeStub::VerifyManifest(const std::vector<std::uint8_t>& manifestBlob, std::uint32_t expectedCrc) const {
    return Crc32(manifestBlob) == expectedCrc;
}

bool RuntimeStub::RelocateIfNeeded(RuntimeContext& ctx) const {
    return ctx.loadBase == ctx.preferredBase || ctx.loadBase != 0;
}

bool RuntimeStub::RebuildImports() const { return true; }

bool RuntimeStub::DecryptAndDecompressSections(std::vector<std::uint8_t>& image) const {
    for (auto& b : image) {
        b ^= 0x5Au;
    }
    return true;
}

bool RuntimeStub::RestoreProtectionsAndJump(const RuntimeContext& ctx) const {
    return ctx.oep != 0;
}

} // namespace ironlock::packer
