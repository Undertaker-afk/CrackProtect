#pragma once
#include <cstdint>
#include <string_view>

namespace IronLock::Core::Hashing {

// FNV-1a 32-bit constants
constexpr uint32_t FNV32_OFFSET_BASIS = 0x811C9DC5;
constexpr uint32_t FNV32_PRIME = 0x01000193;

// FNV-1a 64-bit constants
constexpr uint64_t FNV64_OFFSET_BASIS = 0xCBF29CE484222325ULL;
constexpr uint64_t FNV64_PRIME = 0x100000001B3ULL;

// Production-ready FNV-1a 32-bit
constexpr uint32_t HashString32(std::string_view str) {
    uint32_t hash = FNV32_OFFSET_BASIS;
    for (char c : str) {
        hash ^= static_cast<uint8_t>(c);
        hash *= FNV32_PRIME;
    }
    return hash;
}

// Production-ready FNV-1a 64-bit
constexpr uint64_t HashString64(std::string_view str) {
    uint64_t hash = FNV64_OFFSET_BASIS;
    for (char c : str) {
        hash ^= static_cast<uint8_t>(c);
        hash *= FNV64_PRIME;
    }
    return hash;
}

// Support for wide strings
constexpr uint32_t HashString32W(std::wstring_view str) {
    uint32_t hash = FNV32_OFFSET_BASIS;
    for (wchar_t c : str) {
        hash ^= static_cast<uint8_t>(c & 0xFF);
        hash *= FNV32_PRIME;
        hash ^= static_cast<uint8_t>((c >> 8) & 0xFF);
        hash *= FNV32_PRIME;
    }
    return hash;
}

// Alias for common usage
constexpr uint32_t HashString(std::string_view str) { return HashString32(str); }
constexpr uint32_t HashStringW(std::wstring_view str) { return HashString32W(str); }

} // namespace IronLock::Core::Hashing
