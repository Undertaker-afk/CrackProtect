/**
 * IronLock Hardware ID (HWID) Licensing System
 * 
 * Provides hardware-bound license validation with weighted scoring
 * of multiple hardware identifiers to create a unique machine fingerprint.
 * 
 * Features:
 * - Multi-component HWID generation (CPU, Disk, MAC, BIOS, GPU)
 * - Weighted scoring system for tolerance to minor hardware changes
 * - AES-256 encrypted license files
 * - Online/offline activation support
 * - Graceful degradation for VM/container environments
 * 
 * @author IronLock Team
 * @license MIT (Educational Purpose)
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include "../crypto/AES256.h"

namespace IronLock {

// HWID Component weights for scoring system
enum class HWIDComponent : uint8_t {
    CPU_ID          = 0x01,  // Weight: 30% - Most stable
    DISK_SERIAL     = 0x02,  // Weight: 25% - Very stable
    MAC_ADDRESS     = 0x03,  // Weight: 20% - Can change with network
    BIOS_UUID       = 0x04,  // Weight: 15% - Stable on physical
    GPU_ID          = 0x05,  // Weight: 10% - Can change with drivers
    MOTHERBOARD_ID  = 0x06   // Weight: 15% - Very stable
};

struct HWIDFingerprint {
    std::string cpu_id;
    std::string disk_serial;
    std::string mac_address;
    std::string bios_uuid;
    std::string gpu_id;
    std::string motherboard_id;
    
    // Combined hash
    std::string composite_hash;
    
    // Individual component hashes
    std::vector<std::pair<HWIDComponent, std::string>> components;
    
    // Generation timestamp
    uint64_t timestamp;
    
    // Confidence score (0-100)
    uint8_t confidence_score;
};

struct LicenseData {
    // License metadata
    std::wstring license_id;
    std::wstring customer_name;
    std::wstring company_name;
    
    // License type
    enum class LicenseType : uint8_t {
        PERPETUAL     = 0x01,
        SUBSCRIPTION  = 0x02,
        TRIAL         = 0x03,
        FLOATING      = 0x04,
        OEM           = 0x05
    };
    
    LicenseType type;
    
    // Time restrictions
    uint64_t issue_date;      // Unix timestamp
    uint64_t expiry_date;     // Unix timestamp (0 = never)
    uint32_t max_activations; // 0 = unlimited
    
    // Hardware binding
    HWIDFingerprint bound_hwid;
    uint8_t tolerance_threshold; // 0-100, how much HW can change
    
    // Feature flags
    uint64_t feature_flags;
    
    // Encrypted signature
    std::vector<uint8_t> signature;
    
    // Activation count
    uint32_t current_activations;
};

class HWIDLicensing {
public:
    HWIDLicensing();
    ~HWIDLicensing();
    
    /**
     * Generate comprehensive HWID fingerprint for current machine
     * @param include_all Include all components even if unavailable
     * @return HWIDFingerprint with confidence score
     */
    HWIDFingerprint generateFingerprint(bool include_all = true);
    
    /**
     * Calculate similarity score between two fingerprints
     * @param fp1 First fingerprint
     * @param fp2 Second fingerprint
     * @return Similarity percentage (0-100)
     */
    uint8_t calculateSimilarity(const HWIDFingerprint& fp1, 
                                const HWIDFingerprint& fp2);
    
    /**
     * Create new license bound to current hardware
     * @param license_data License metadata
     * @param encryption_key AES-256 key for license encryption
     * @return Encrypted license blob
     */
    std::vector<uint8_t> createLicense(LicenseData& license_data,
                                       const std::vector<uint8_t>& encryption_key);
    
    /**
     * Validate license against current hardware
     * @param license_blob Encrypted license data
     * @param encryption_key AES-256 decryption key
     * @param tolerance Override default tolerance threshold
     * @return Validation result
     */
    enum class ValidationResult {
        VALID,
        EXPIRED,
        HWID_MISMATCH,
        INVALID_SIGNATURE,
        MAX_ACTIVATIONS_REACHED,
        CORRUPTED,
        DECRYPTION_FAILED
    };
    
    ValidationResult validateLicense(const std::vector<uint8_t>& license_blob,
                                   const std::vector<uint8_t>& encryption_key,
                                   uint8_t tolerance = 75);
    
    /**
     * Activate license (increment activation count)
     * @param license_blob License data (will be updated)
     * @param encryption_key Encryption key
     * @return Success status
     */
    bool activateLicense(std::vector<uint8_t>& license_blob,
                        const std::vector<uint8_t>& encryption_key);
    
    /**
     * Export license to file
     * @param license_blob Encrypted license
     * @param filepath Output path
     * @return Success status
     */
    bool exportLicenseToFile(const std::vector<uint8_t>& license_blob,
                            const std::wstring& filepath);
    
    /**
     * Import license from file
     * @param filepath License file path
     * @return Encrypted license blob
     */
    std::vector<uint8_t> importLicenseFromFile(const std::wstring& filepath);
    
    /**
     * Generate offline activation request
     * @param fingerprint Current HWID
     * @return Base64 encoded request string
     */
    std::wstring generateOfflineRequest(const HWIDFingerprint& fingerprint);
    
    /**
     * Parse offline activation response
     * @param response Base64 encoded response
     * @param encryption_key Decryption key
     * @return License blob or empty on failure
     */
    std::vector<uint8_t> parseOfflineResponse(const std::wstring& response,
                                              const std::vector<uint8_t>& encryption_key);

private:
    // Hardware detection methods
    std::string getCPUID();
    std::string getDiskSerial();
    std::string getMACAddress();
    std::string getBIOSUUID();
    std::string getGPUID();
    std::string getMotherboardID();
    
    // Hashing utilities
    std::string hashComponent(const std::string& data, HWIDComponent type);
    std::string generateCompositeHash(const HWIDFingerprint& fp);
    
    // Signature generation
    std::vector<uint8_t> generateSignature(const LicenseData& license,
                                          const std::vector<uint8_t>& key);
    bool verifySignature(const LicenseData& license,
                        const std::vector<uint8_t>& signature,
                        const std::vector<uint8_t>& key);
    
    // Helper functions
    std::string bytesToHex(const uint8_t* data, size_t len);
    std::wstring utf8_to_wstr(const std::string& str);
    std::string wstr_to_utf8(const std::wstring& wstr);
    
    AES256 crypto_;
};

} // namespace IronLock
