#pragma once
#include <cstdint>
#include <vector>

namespace IronLock::Core::Crypto {

// Simple but effective XOR-based string obfuscation for internal use
// To be replaced by more robust AES where requested
class ObfuscatedString {
public:
    template<size_t N>
    constexpr ObfuscatedString(const char (&str)[N], uint32_t key) : m_key(key) {
        for (size_t i = 0; i < N; ++i) {
            m_data[i] = str[i] ^ static_cast<char>((key >> (i % 4)) & 0xFF);
        }
        m_size = N;
    }

    void Decrypt(char* out) const {
        for (size_t i = 0; i < m_size; ++i) {
            out[i] = m_data[i] ^ static_cast<char>((m_key >> (i % 4)) & 0xFF);
        }
    }

private:
    char m_data[256] = {0};
    uint32_t m_key;
    size_t m_size;
};

// AES-256 implementation (Simplified for brevity, but functional)
void AES256_Encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, size_t len, uint8_t* output);
void AES256_Decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* input, size_t len, uint8_t* output);

} // namespace IronLock::Core::Crypto
