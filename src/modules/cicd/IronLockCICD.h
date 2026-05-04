#pragma once
/**
 * IronLock CI/CD Integration Module
 * 
 * Provides native integration with popular CI/CD platforms:
 * - GitHub Actions
 * - GitLab CI
 * - Jenkins
 * - Azure DevOps
 * - Docker build pipelines
 * 
 * Features:
 * - Automated protection during build
 * - Profile selection based on build type
 * - Artifact signing integration
 * - Build reproducibility verification
 */

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace ironlock {

enum class CIPlatform {
    Unknown,
    GitHubActions,
    GitLabCI,
    Jenkins,
    AzureDevOps,
    CircleCI,
    TravisCI,
    Docker
};

struct CICDConfig {
    CIPlatform platform;
    std::string profilePath;
    std::string outputDir;
    bool enableSigning;
    bool verifyReproducibility;
    std::vector<std::string> protectedBinaries;
    std::map<std::string, std::string> environmentVars;
};

/**
 * CI/CD Platform Detector
 * Automatically detects the running CI/CD platform
 */
class PlatformDetector {
public:
    static CIPlatform detectCurrentPlatform();
    static std::string getPlatformName(CIPlatform platform);
    static bool isRunningInCI();
    
private:
    static bool checkGitHubActions();
    static bool checkGitLabCI();
    static bool checkJenkins();
    static bool checkAzureDevOps();
    static bool checkDocker();
};

/**
 * Build Configuration Manager
 * Manages protection profiles based on build configuration
 */
class BuildConfigManager {
public:
    BuildConfigManager(const CICDConfig &config);
    
    void loadProfile(const std::string &profilePath);
    void applyProtection(const std::string &binaryPath);
    bool verifyBuild(const std::string &originalPath, const std::string &protectedPath);
    
    // Build type detection
    bool isReleaseBuild() const;
    bool isDebugBuild() const;
    bool isCIBuild() const;
    
private:
    CICDConfig config_;
    std::map<std::string, int> protectionLevels_;
    void detectBuildType();
};

/**
 * Artifact Signer
 * Integrates with code signing infrastructure
 */
class ArtifactSigner {
public:
    enum class SignMethod {
        None,
        SignTool,      // Windows signtool.exe
        OpenSSL,       // OpenSSL-based signing
        AzureKeyVault, // Azure Key Vault integration
        AWSSigning,    // AWS Signer
        Custom         // Custom signing script
    };
    
    ArtifactSigner(SignMethod method);
    
    bool signFile(const std::string &filePath);
    bool signFileWithTimestamp(const std::string &filePath, const std::string &timestampUrl);
    bool verifySignature(const std::string &filePath);
    
    static std::unique_ptr<ArtifactSigner> createFromEnvironment();
    
private:
    SignMethod method_;
    std::string certificatePath_;
    std::string privateKeyPath_;
    
    bool signWithSignTool(const std::string &filePath);
    bool signWithOpenSSL(const std::string &filePath);
    bool signWithAzureKV(const std::string &filePath);
};

/**
 * ReproducibilityVerifier
 * Ensures builds are reproducible and untampered
 */
class ReproducibilityVerifier {
public:
    struct VerificationResult {
        bool success;
        std::string hashOriginal;
        std::string hashProtected;
        std::string errorMessage;
    };
    
    ReproducibilityVerifier();
    
    VerificationResult verify(const std::string &inputFile, const std::string &outputFile);
    VerificationResult verifyAgainstBaseline(const std::string &file, const std::string &baselineHash);
    
    static std::string computeSHA256(const std::string &filePath);
    static std::string computeHashWithMetadata(const std::string &filePath, const std::map<std::string, std::string> &metadata);
    
private:
    bool compareHashes(const std::string &hash1, const std::string &hash2);
};

/**
 * GitHub Actions Integration
 */
class GitHubActionsIntegration {
public:
    static void setOutput(const std::string &name, const std::string &value);
    static void addMask(const std::string &value);
    static void startGroup(const std::string &name);
    static void endGroup();
    static void logWarning(const std::string &message);
    static void logError(const std::string &message);
    
    struct WorkflowContext {
        std::string eventName;
        std::string ref;
        std::string sha;
        std::string actor;
        std::string repository;
        std::string workflow;
        bool isPR;
    };
    
    static WorkflowContext getContext();
};

/**
 * GitLab CI Integration
 */
class GitLabCIIntegration {
public:
    struct CIContext {
        std::string ciCommitSha;
        std::string ciCommitRefName;
        std::string ciJobId;
        std::string ciPipelineId;
        std::string ciProjectDir;
        std::string ciRunnerId;
        std::string ciStage;
        bool isManualJob;
    };
    
    static CIContext getContext();
    static void printSection(const std::string &title);
    static void printCollapsibleSection(const std::string &title, const std::string &content);
};

/**
 * Docker Build Integration
 * Handles protection in containerized build environments
 */
class DockerBuildIntegration {
public:
    struct BuildConfig {
        std::string baseImage;
        std::vector<std::string> buildArgs;
        std::vector<std::string> volumes;
        std::string workdir;
        bool multiStage;
    };
    
    static BuildConfig parseDockerfile(const std::string &dockerfilePath);
    static bool injectProtectionLayer(const std::string &dockerfilePath, const std::string &protectionConfig);
    static bool createMinimalRuntimeImage(const std::string &protectedBinary, const std::string &outputImage);
    
    // Multi-stage build optimization
    static std::string generateMultiStageDockerfile(
        const std::string &buildImage,
        const std::string &runtimeImage,
        const std::string &protectedBinary,
        const std::vector<std::string> &dependencies
    );
};

/**
 * Main CI/CD Orchestrator
 * Coordinates all CI/CD integration components
 */
class CICDOrchestrator {
public:
    CICDOrchestrator();
    ~CICDOrchestrator();
    
    bool initialize(const CICDConfig &config);
    bool runProtectionPipeline(const std::vector<std::string> &binaries);
    bool generateBuildReport(const std::string &outputPath);
    bool uploadArtifacts(const std::vector<std::string> &paths);
    
    // Pipeline stages
    bool stageDetect();
    bool stageConfigure();
    bool stageProtect();
    bool stageSign();
    bool stageVerify();
    bool stageReport();
    
private:
    CICDConfig config_;
    std::unique_ptr<BuildConfigManager> configManager_;
    std::unique_ptr<ArtifactSigner> signer_;
    std::unique_ptr<ReproducibilityVerifier> verifier_;
    CIPlatform detectedPlatform_;
    
    std::vector<std::function<bool()>> pipelineStages_;
    void setupPipeline();
};

// Factory functions
std::unique_ptr<CICDOrchestrator> createCICDOrchestrator();
CICDConfig loadConfigFromEnvironment();

} // namespace ironlock
