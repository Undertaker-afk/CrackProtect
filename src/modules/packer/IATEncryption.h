#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>

namespace IronLock::Modules::Packer {

struct ImportEntry {
    std::string moduleName;
    std::string functionName;
    uint32_t rva;
    uint16_t hint;
    bool byOrdinal;
};

struct EncryptedIAT {
    std::vector<uint8_t> encryptedTable;
    std::vector<uint8_t> decryptionKey;
    uint32_t originalRVA;
    uint32_t size;
    uint64_t nonce;
};

class IATEncryptor {
public:
    static EncryptedIAT EncryptIAT(const std::vector<ImportEntry>& imports, uint64_t seed);
    static std::vector<uint8_t> GenerateDecryptStub(const EncryptedIAT& encrypted);
    static void ApplyIATProtection(std::vector<uint8_t>& peImage, const EncryptedIAT& encrypted);
    
private:
    static std::vector<uint8_t> DeriveKey(uint64_t seed, size_t length);
    static void XOREncrypt(uint8_t* data, size_t len, const uint8_t* key, size_t keyLen);
};

} // namespace IronLock::Modules::Packer
