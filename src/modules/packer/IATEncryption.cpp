#include "IATEncryption.h"
#include <cstring>
#include <algorithm>

namespace IronLock::Modules::Packer {

std::vector<uint8_t> IATEncryptor::DeriveKey(uint64_t seed, size_t length) {
    std::vector<uint8_t> key(length);
    uint64_t state = seed ^ 0x9E3779B97F4A7C15ULL;
    
    for (size_t i = 0; i < length; ++i) {
        state ^= state >> 33;
        state *= 0xFF51AFD7ED558CCDULL;
        state ^= state >> 33;
        state *= 0xC4CEB9FE1A85EC53ULL;
        state ^= state >> 33;
        key[i] = static_cast<uint8_t>(state & 0xFF);
    }
    return key;
}

void IATEncryptor::XOREncrypt(uint8_t* data, size_t len, const uint8_t* key, size_t keyLen) {
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= key[i % keyLen];
        data[i] ^= static_cast<uint8_t>((i * 137) & 0xFF);
    }
}

EncryptedIAT IATEncryptor::EncryptIAT(const std::vector<ImportEntry>& imports, uint64_t seed) {
    EncryptedIAT result;
    result.nonce = seed ^ 0xDEADBEEFCAFEBABEULL;
    
    // Calculate total IAT size (8 bytes per entry for x64, 4 for x86)
    result.size = static_cast<uint32_t>(imports.size() * sizeof(uint64_t));
    result.encryptedTable.resize(result.size);
    
    // Fill encrypted table with placeholder addresses
    for (size_t i = 0; i < imports.size(); ++i) {
        uint64_t placeholder = (static_cast<uint64_t>(imports[i].hint) << 32) | (i & 0xFFFFFFFF);
        std::memcpy(result.encryptedTable.data() + (i * 8), &placeholder, 8);
    }
    
    // Generate and apply encryption key
    result.decryptionKey = DeriveKey(result.nonce, 64);
    XOREncrypt(result.encryptedTable.data(), result.encryptedTable.size(), 
               result.decryptionKey.data(), result.decryptionKey.size());
    
    return result;
}

std::vector<uint8_t> IATEncryptor::GenerateDecryptStub(const EncryptedIAT& encrypted) {
    std::vector<uint8_t> stub;
    
    // x64 shellcode stub for IAT decryption at runtime
    // This is a simplified version - production would be more sophisticated
    
    // push rbx
    stub.push_back(0x53);
    // push rsi  
    stub.push_back(0x56);
    // push rdi
    stub.push_back(0x57);
    
    // mov rdi, IAT_address (placeholder)
    stub.push_back(0xBF);
    uint32_t iatAddr = encrypted.originalRVA;
    stub.insert(stub.end(), reinterpret_cast<uint8_t*>(&iatAddr), reinterpret_cast<uint8_t*>(&iatAddr) + 4);
    
    // mov rcx, size
    stub.push_back(0xB9);
    uint32_t size = encrypted.size;
    stub.insert(stub.end(), reinterpret_cast<uint8_t*>(&size), reinterpret_cast<uint8_t*>(&size) + 4);
    
    // mov rsi, key_ptr (placeholder - key embedded after code)
    stub.push_back(0xBE);
    uint32_t keyOffset = static_cast<uint32_t>(stub.size() + 4);
    stub.insert(stub.end(), reinterpret_cast<uint8_t*>(&keyOffset), reinterpret_cast<uint8_t*>(&keyOffset) + 4);
    
    // decrypt_loop:
    // mov eax, [rsi + rcx*4 % keylen]
    // xor [rdi + rcx*8], eax
    // loop decrypt_loop
    
    // Simplified: just mark where decryption happens
    // In production this would be full metamorphic decryption code
    
    // pop rdi
    stub.push_back(0x5F);
    // pop rsi
    stub.push_back(0x5E);
    // pop rbx
    stub.push_back(0x5B);
    // ret
    stub.push_back(0xC3);
    
    // Append encrypted key
    stub.insert(stub.end(), encrypted.decryptionKey.begin(), encrypted.decryptionKey.end());
    
    return stub;
}

void IATEncryptor::ApplyIATProtection(std::vector<uint8_t>& peImage, const EncryptedIAT& encrypted) {
    if (encrypted.originalRVA == 0 || encrypted.originalRVA >= peImage.size()) {
        return;
    }
    
    // Encrypt the IAT in-place in the PE image
    size_t offset = encrypted.originalRVA;
    size_t endOffset = std::min(offset + encrypted.size, peImage.size());
    
    auto key = DeriveKey(encrypted.nonce, 64);
    XOREncrypt(peImage.data() + offset, endOffset - offset, key.data(), key.size());
}

} // namespace IronLock::Modules::Packer
