#pragma once
#include <cstdint>
#include <string_view>

namespace IronLock::Core::Hashing {

// FNV-1a 32-bit constants
constexpr uint32_t FNV_OFFSET_BASIS = 0x811C9DC5;
constexpr uint32_t FNV_PRIME = 0x01000193;

// Compile-time FNV-1a hash
constexpr uint32_t HashString(std::string_view str) {
    uint32_t hash = FNV_OFFSET_BASIS;
    for (char c : str) {
        hash ^= static_cast<uint8_t>(c);
        hash *= FNV_PRIME;
    }
    return hash;
}

// Compile-time FNV-1a hash (wide string)
constexpr uint32_t HashStringW(std::wstring_view str) {
    uint32_t hash = FNV_OFFSET_BASIS;
    for (wchar_t c : str) {
        // Simple downcast for hashing, assuming ASCII-compatible wide chars for system names
        hash ^= static_cast<uint8_t>(c & 0xFF);
        hash *= FNV_PRIME;
        hash ^= static_cast<uint8_t>((c >> 8) & 0xFF);
        hash *= FNV_PRIME;
    }
    return hash;
}

} // namespace IronLock::Core::Hashing
