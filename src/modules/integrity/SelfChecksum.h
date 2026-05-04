#pragma once
/**
 * IronLock Self-Checksumming & Anti-Hooking Module
 * 
 * Provides runtime integrity verification and anti-tampering capabilities:
 * - Self-checksumming with triple-redundant hashing
 * - Automatic code section healing
 * - Anti-hooking detection (inline, IAT, EAT hooks)
 * - Memory page integrity monitoring
 * - PE header protection
 */

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <map>

#ifdef _WIN32
    #include <windows.h>
#endif

namespace ironlock {

enum class IntegrityLevel {
    None = 0,
    Basic = 1,      // Simple checksum
    Enhanced = 2,   // Multiple hashes + timing
    Maximum = 3     // Full verification + healing
};

struct SectionHash {
    std::string sectionName;
    uint64_t offset;
    uint64_t size;
    std::vector<uint8_t> hashMD5;
    std::vector<uint8_t> hashSHA256;
    std::vector<uint8_t> hashCustom;
    uint32_t crc32;
    bool verified;
};

struct HookDetectionResult {
    bool isHooked;
    std::string functionName;
    void* functionAddress;
    void* hookAddress;
    std::string hookType; // "inline", "iat", "eat", "veh"
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> currentBytes;
};

/**
 * TripleHash Engine
 * Computes three different hashes for redundancy
 */
class TripleHashEngine {
public:
    struct HashResult {
        std::vector<uint8_t> md5;
        std::vector<uint8_t> sha256;
        std::vector<uint8_t> custom;
        uint32_t crc32;
    };
    
    static HashResult compute(const uint8_t* data, size_t size);
    static HashResult computeFile(const std::string& filePath);
    
private:
    static std::vector<uint8_t> computeMD5(const uint8_t* data, size_t size);
    static std::vector<uint8_t> computeSHA256(const uint8_t* data, size_t size);
    static std::vector<uint8_t> computeCustom(const uint8_t* data, size_t size);
    static uint32_t computeCRC32(const uint8_t* data, size_t size);
};

/**
 * SelfChecksummer
 * Monitors and verifies own code integrity
 */
class SelfChecksummer {
public:
    SelfChecksummer(IntegrityLevel level = IntegrityLevel::Enhanced);
    ~SelfChecksummer();
    
    bool initialize();
    bool verifyAllSections();
    bool verifySection(const std::string& sectionName);
    
    // Continuous monitoring
    void startMonitoring(int intervalMs);
    void stopMonitoring();
    bool isMonitoring() const;
    
    // Callbacks for integrity violations
    using ViolationCallback = std::function<void(const SectionHash&, bool)>;
    void setViolationCallback(ViolationCallback callback);
    
    // Get verification results
    std::vector<SectionHash> getSectionHashes() const;
    bool getLastVerificationResult() const;
    
private:
    IntegrityLevel level_;
    std::vector<SectionHash> baselineHashes_;
    std::vector<SectionHash> currentHashes_;
    ViolationCallback violationCallback_;
    bool monitoring_;
    int monitorInterval_;
    
#ifdef _WIN32
    HANDLE hCurrentProcess_;
#endif
    
    bool captureBaseline();
    bool verifySectionInternal(SectionHash& section);
    void monitoringThread();
};

/**
 * CodeHealer
 * Automatically repairs tampered code sections
 */
class CodeHealer {
public:
    struct HealingResult {
        bool success;
        std::string sectionName;
        size_t bytesRepaired;
        std::string errorMessage;
    };
    
    CodeHealer();
    
    HealingResult healSection(const SectionHash& baseline, const std::string& sectionName);
    HealingResult healFunction(void* functionStart, const std::vector<uint8_t>& originalBytes);
    
    // Backup management
    bool createBackup(const std::string& outputPath);
    bool restoreFromBackup(const std::string& backupPath);
    
private:
    std::map<std::string, std::vector<uint8_t>> backups_;
    
    bool writeProtectedMemory(void* address, const uint8_t* data, size_t size);
    bool unprotectMemory(void* address, size_t size);
    bool reprotectMemory(void* address, size_t size);
};

/**
 * AntiHookDetector
 * Detects various types of API hooking
 */
class AntiHookDetector {
public:
    AntiHookDetector();
    
    // Scan for hooks in loaded modules
    std::vector<HookDetectionResult> scanModule(const std::string& moduleName);
    std::vector<HookDetectionResult> scanAllModules();
    
    // Check specific functions
    HookDetectionResult checkFunction(const std::string& moduleName, const std::string& functionName);
    HookDetectionResult checkFunction(void* functionPtr);
    
    // Detection methods
    bool detectInlineHook(void* functionPtr, HookDetectionResult& result);
    bool detectIATHook(const std::string& moduleName, HookDetectionResult& result);
    bool detectEATHook(const std::string& moduleName, HookDetectionResult& result);
    bool detectVEHHook(HookDetectionResult& result);
    
    // Get clean function bytes from disk
    std::vector<uint8_t> getOriginalFunctionBytes(const std::string& modulePath, 
                                                   const std::string& functionName,
                                                   size_t numBytes = 16);
    
private:
    bool isPrologueInstruction(uint8_t byte);
    bool containsJmpOrCall(const uint8_t* bytes, size_t size);
    void* resolveFunctionAddress(const std::string& moduleName, const std::string& functionName);
};

/**
 * PEHeaderProtector
 * Protects PE headers from modification
 */
class PEHeaderProtector {
public:
    PEHeaderProtector();
    
    bool protect();
    bool verify();
    bool hide();  // Erase PE headers from memory
    
    struct PEHeaderHash {
        std::vector<uint8_t> dosHeaderHash;
        std::vector<uint8_t> ntHeaderHash;
        std::vector<uint8_t> sectionHeadersHash;
        std::vector<uint8_t> importTableHash;
    };
    
    PEHeaderHash captureHeaderHashes();
    bool verifyHeaderHashes(const PEHeaderHash& baseline);
    
private:
    PEHeaderHash baseline_;
    bool protected_;
    
    void* getDOSHeader();
    void* getNTHeaders();
    void* getSectionHeaders();
    void* getImportTable();
};

/**
 * MemoryPageMonitor
 * Monitors memory pages for unauthorized modifications
 */
class MemoryPageMonitor {
public:
    struct Pageinfo {
        void* baseAddress;
        size_t size;
        uint32_t protection;
        uint32_t type;
        std::vector<uint8_t> hash;
        bool monitored;
    };
    
    MemoryPageMonitor();
    
    bool addPageToMonitor(void* address);
    bool removePageFromMonitor(void* address);
    bool verifyAllPages();
    bool verifyPage(void* address);
    
    std::vector<Pageinfo> getMonitoredPages() const;
    
private:
    std::map<void*, Pageinfo> monitoredPages_;
    
    bool capturePageHash(Pageinfo& page);
    bool verifyPageHash(const Pageinfo& page);
};

/**
 * IntegrityManager
 * Main coordinator for all integrity features
 */
class IntegrityManager {
public:
    struct Config {
        IntegrityLevel level;
        bool enableSelfChecksum;
        bool enableAutoHealing;
        bool enableAntiHook;
        bool enablePEProtection;
        bool enablePageMonitoring;
        int verificationIntervalMs;
        std::vector<std::string> protectedModules;
    };
    
    IntegrityManager(const Config& config = Config());
    ~IntegrityManager();
    
    bool initialize();
    bool verify();
    
    // Individual component access
    SelfChecksummer* getChecksummer();
    AntiHookDetector* getHookDetector();
    PEHeaderProtector* getPEProtector();
    CodeHealer* getHealer();
    
    // Quick integrity check
    bool quickCheck();
    
    // Full integrity verification
    struct FullReport {
        bool overallStatus;
        bool selfChecksumOk;
        bool noHooksDetected;
        bool peHeadersOk;
        bool memoryPagesOk;
        std::vector<std::string> issues;
    };
    
    FullReport generateFullReport();
    
private:
    Config config_;
    std::unique_ptr<SelfChecksummer> checksummer_;
    std::unique_ptr<AntiHookDetector> hookDetector_;
    std::unique_ptr<PEHeaderProtector> peProtector_;
    std::unique_ptr<CodeHealer> healer_;
    std::unique_ptr<MemoryPageMonitor> pageMonitor_;
    
    void onIntegrityViolation(const SectionHash& section, bool isTampered);
};

// Factory function
std::unique_ptr<IntegrityManager> createIntegrityManager(IntegrityLevel level = IntegrityLevel::Enhanced);

} // namespace ironlock
