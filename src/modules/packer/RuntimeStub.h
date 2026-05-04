#pragma once

#include <cstdint>
#include <vector>

namespace ironlock::packer {

struct RuntimeContext {
    std::uintptr_t loadBase;
    std::uintptr_t preferredBase;
    std::uintptr_t oep;
};

class RuntimeStub {
public:
    bool VerifyManifest(const std::vector<std::uint8_t>& manifestBlob, std::uint32_t expectedCrc) const;
    bool RelocateIfNeeded(RuntimeContext& ctx) const;
    bool RebuildImports() const;
    bool DecryptAndDecompressSections(std::vector<std::uint8_t>& image) const;
    bool RestoreProtectionsAndJump(const RuntimeContext& ctx) const;
};

} // namespace ironlock::packer
