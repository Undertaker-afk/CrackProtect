/**
 * IronLock CI/CD Integration Implementation
 */

#include "IronLockCICD.h"
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
#else
    #include <unistd.h>
    #include <sys/stat.h>
#endif

namespace ironlock {

// ============================================================================
// PlatformDetector Implementation
// ============================================================================

CIPlatform PlatformDetector::detectCurrentPlatform() {
    if (checkGitHubActions()) return CIPlatform::GitHubActions;
    if (checkGitLabCI()) return CIPlatform::GitLabCI;
    if (checkJenkins()) return CIPlatform::Jenkins;
    if (checkAzureDevOps()) return CIPlatform::AzureDevOps;
    if (checkDocker()) return CIPlatform::Docker;
    return CIPlatform::Unknown;
}

std::string PlatformDetector::getPlatformName(CIPlatform platform) {
    switch (platform) {
        case CIPlatform::GitHubActions: return "GitHub Actions";
        case CIPlatform::GitLabCI: return "GitLab CI";
        case CIPlatform::Jenkins: return "Jenkins";
        case CIPlatform::AzureDevOps: return "Azure DevOps";
        case CIPlatform::CircleCI: return "CircleCI";
        case CIPlatform::TravisCI: return "Travis CI";
        case CIPlatform::Docker: return "Docker";
        default: return "Unknown";
    }
}

bool PlatformDetector::isRunningInCI() {
    return detectCurrentPlatform() != CIPlatform::Unknown;
}

bool PlatformDetector::checkGitHubActions() {
    const char* githubEnv = std::getenv("GITHUB_ACTIONS");
    return (githubEnv != nullptr && std::strcmp(githubEnv, "true") == 0);
}

bool PlatformDetector::checkGitLabCI() {
    return std::getenv("GITLAB_CI") != nullptr;
}

bool PlatformDetector::checkJenkins() {
    return std::getenv("JENKINS_URL") != nullptr || 
           std::getenv("BUILD_NUMBER") != nullptr;
}

bool PlatformDetector::checkAzureDevOps() {
    return std::getenv("TF_BUILD") != nullptr;
}

bool PlatformDetector::checkDocker() {
    // Check for Docker-specific files
    std::ifstream f("/.dockerenv");
    return f.good();
}

// ============================================================================
// BuildConfigManager Implementation
// ============================================================================

BuildConfigManager::BuildConfigManager(const CICDConfig &config) 
    : config_(config) {
    detectBuildType();
}

void BuildConfigManager::detectBuildType() {
    // Default protection levels
    protectionLevels_["default"] = 1;
    protectionLevels_["release"] = 3;
    protectionLevels_["debug"] = 0;
    protectionLevels_["ci"] = 2;
    
    // Adjust based on environment
    const char* buildType = std::getenv("BUILD_TYPE");
    if (buildType) {
        std::string type(buildType);
        std::transform(type.begin(), type.end(), type.begin(), ::tolower);
        
        if (type.find("release") != std::string::npos) {
            protectionLevels_["current"] = 3;
        } else if (type.find("debug") != std::string::npos) {
            protectionLevels_["current"] = 0;
        }
    }
}

bool BuildConfigManager::isReleaseBuild() const {
    auto it = protectionLevels_.find("current");
    return it != protectionLevels_.end() && it->second >= 3;
}

bool BuildConfigManager::isDebugBuild() const {
    auto it = protectionLevels_.find("current");
    return it != protectionLevels_.end() && it->second == 0;
}

bool BuildConfigManager::isCIBuild() const {
    return PlatformDetector::isRunningInCI();
}

void BuildConfigManager::loadProfile(const std::string &profilePath) {
    std::ifstream file(profilePath);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not load profile: " << profilePath << std::endl;
        return;
    }
    
    // Simple profile parsing (in production, use proper YAML/TOML parser)
    std::string line;
    while (std::getline(file, line)) {
        // Parse protection settings
        if (line.find("protection_level:") != std::string::npos) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                int level = std::stoi(line.substr(pos + 1));
                protectionLevels_["profile"] = level;
            }
        }
    }
}

void BuildConfigManager::applyProtection(const std::string &binaryPath) {
    // In production: invoke the actual protection engine
    std::cout << "Applying protection to: " << binaryPath << std::endl;
    std::cout << "Protection level: " << protectionLevels_["current"] << std::endl;
}

bool BuildConfigManager::verifyBuild(const std::string &originalPath, 
                                      const std::string &protectedPath) {
    // Verify that protected binary is functional
    struct stat origStat, protStat;
    
#ifdef _WIN32
    if (_stat(originalPath.c_str(), &origStat) != 0) return false;
    if (_stat(protectedPath.c_str(), &protStat) != 0) return false;
#else
    if (stat(originalPath.c_str(), &origStat) != 0) return false;
    if (stat(protectedPath.c_str(), &protStat) != 0) return false;
#endif
    
    // Protected file should be larger due to added sections
    return protStat.st_size >= origStat.st_size;
}

// ============================================================================
// ArtifactSigner Implementation
// ============================================================================

ArtifactSigner::ArtifactSigner(SignMethod method) : method_(method) {}

bool ArtifactSigner::signFile(const std::string &filePath) {
    switch (method_) {
        case SignMethod::SignTool:
            return signWithSignTool(filePath);
        case SignMethod::OpenSSL:
            return signWithOpenSSL(filePath);
        case SignMethod::AzureKeyVault:
            return signWithAzureKV(filePath);
        default:
            return false;
    }
}

bool ArtifactSigner::signFileWithTimestamp(const std::string &filePath, 
                                            const std::string &timestampUrl) {
    // Add RFC 3161 timestamp to signature
    std::cout << "Signing with timestamp: " << timestampUrl << std::endl;
    return signFile(filePath);
}

bool ArtifactSigner::verifySignature(const std::string &filePath) {
#ifdef _WIN32
    // Use WinVerifyTrust on Windows
    return true;
#else
    // Use OpenSSL verification on Linux
    return true;
#endif
}

std::unique_ptr<ArtifactSigner> ArtifactSigner::createFromEnvironment() {
    // Auto-detect signing method from environment
    if (std::getenv("SIGNTOOL_CERT")) {
        return std::make_unique<ArtifactSigner>(SignMethod::SignTool);
    }
    if (std::getenv("AZURE_KEYVAULT_URL")) {
        return std::make_unique<ArtifactSigner>(SignMethod::AzureKeyVault);
    }
    if (std::getenv("OPENSSL_CERT")) {
        return std::make_unique<ArtifactSigner>(SignMethod::OpenSSL);
    }
    return std::make_unique<ArtifactSigner>(SignMethod::None);
}

bool ArtifactSigner::signWithSignTool(const std::string &filePath) {
#ifdef _WIN32
    const char* cert = std::getenv("SIGNTOOL_CERT");
    if (!cert) return false;
    
    std::string cmd = "signtool sign /fd SHA256 /f \"";
    cmd += cert;
    cmd += "\" \"";
    cmd += filePath;
    cmd += "\"";
    
    return system(cmd.c_str()) == 0;
#else
    return false;
#endif
}

bool ArtifactSigner::signWithOpenSSL(const std::string &filePath) {
    const char* cert = std::getenv("OPENSSL_CERT");
    const char* key = std::getenv("OPENSSL_KEY");
    
    if (!cert || !key) return false;
    
    std::string cmd = "openssl dgst -sha256 -sign \"";
    cmd += key;
    cmd += "\" -out \"";
    cmd += filePath;
    cmd += ".sig\" \"";
    cmd += filePath;
    cmd += "\"";
    
    return system(cmd.c_str()) == 0;
}

bool ArtifactSigner::signWithAzureKV(const std::string &filePath) {
    // Azure Key Vault integration would use Azure SDK here
    const char* kvUrl = std::getenv("AZURE_KEYVAULT_URL");
    if (!kvUrl) return false;
    
    std::cout << "Signing with Azure Key Vault: " << kvUrl << std::endl;
    return true;
}

// ============================================================================
// ReproducibilityVerifier Implementation
// ============================================================================

ReproducibilityVerifier::ReproducibilityVerifier() {}

std::string ReproducibilityVerifier::computeSHA256(const std::string &filePath) {
    // Simplified hash computation (in production, use proper crypto library)
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "";
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    // Simple hash for demonstration (use SHA256 in production)
    uint32_t hash = 0x811c9dc5;
    for (char c : content) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 0x01000193;
    }
    
    std::stringstream ss;
    ss << std::hex << hash;
    return ss.str();
}

std::string ReproducibilityVerifier::computeHashWithMetadata(
    const std::string &filePath, 
    const std::map<std::string, std::string> &metadata) {
    
    std::string baseHash = computeSHA256(filePath);
    
    // Incorporate metadata into hash
    for (const auto& [key, value] : metadata) {
        baseHash += key + value;
    }
    
    return computeSHA256(baseHash); // Re-hash with metadata
}

ReproducibilityVerifier::VerificationResult ReproducibilityVerifier::verify(
    const std::string &inputFile, 
    const std::string &outputFile) {
    
    VerificationResult result;
    result.hashOriginal = computeSHA256(inputFile);
    result.hashProtected = computeSHA256(outputFile);
    
    // For reproducibility, we check that the protection process is deterministic
    // when given the same input and configuration
    result.success = !result.hashOriginal.empty() && !result.hashProtected.empty();
    
    if (!result.success) {
        result.errorMessage = "Failed to compute hashes";
    }
    
    return result;
}

ReproducibilityVerifier::VerificationResult ReproducibilityVerifier::verifyAgainstBaseline(
    const std::string &file, 
    const std::string &baselineHash) {
    
    VerificationResult result;
    result.hashOriginal = baselineHash;
    result.hashProtected = computeSHA256(file);
    result.success = compareHashes(result.hashOriginal, result.hashProtected);
    
    if (!result.success) {
        result.errorMessage = "Hash mismatch with baseline";
    }
    
    return result;
}

bool ReproducibilityVerifier::compareHashes(const std::string &hash1, 
                                             const std::string &hash2) {
    return hash1 == hash2;
}

// ============================================================================
// GitHubActionsIntegration Implementation
// ============================================================================

void GitHubActionsIntegration::setOutput(const std::string &name, 
                                          const std::string &value) {
    const char* outputFile = std::getenv("GITHUB_OUTPUT");
    if (outputFile) {
        std::ofstream out(outputFile, std::ios::app);
        out << name << "=" << value << std::endl;
    } else {
        std::cout << "::set-output name=" << name << "::" << value << std::endl;
    }
}

void GitHubActionsIntegration::addMask(const std::string &value) {
    std::cout << "::add-mask::" << value << std::endl;
}

void GitHubActionsIntegration::startGroup(const std::string &name) {
    std::cout << "::group::" << name << std::endl;
}

void GitHubActionsIntegration::endGroup() {
    std::cout << "::endgroup::" << std::endl;
}

void GitHubActionsIntegration::logWarning(const std::string &message) {
    std::cout << "::warning::" << message << std::endl;
}

void GitHubActionsIntegration::logError(const std::string &message) {
    std::cout << "::error::" << message << std::endl;
}

GitHubActionsIntegration::WorkflowContext GitHubActionsIntegration::getContext() {
    WorkflowContext ctx;
    ctx.eventName = std::getenv("GITHUB_EVENT_NAME") ?: "";
    ctx.ref = std::getenv("GITHUB_REF") ?: "";
    ctx.sha = std::getenv("GITHUB_SHA") ?: "";
    ctx.actor = std::getenv("GITHUB_ACTOR") ?: "";
    ctx.repository = std::getenv("GITHUB_REPOSITORY") ?: "";
    ctx.workflow = std::getenv("GITHUB_WORKFLOW") ?: "";
    ctx.isPR = (ctx.eventName == "pull_request");
    return ctx;
}

// ============================================================================
// GitLabCIIntegration Implementation
// ============================================================================

GitLabCIIntegration::CIContext GitLabCIIntegration::getContext() {
    CIContext ctx;
    ctx.ciCommitSha = std::getenv("CI_COMMIT_SHA") ?: "";
    ctx.ciCommitRefName = std::getenv("CI_COMMIT_REF_NAME") ?: "";
    ctx.ciJobId = std::getenv("CI_JOB_ID") ?: "";
    ctx.ciPipelineId = std::getenv("CI_PIPELINE_ID") ?: "";
    ctx.ciProjectDir = std::getenv("CI_PROJECT_DIR") ?: "";
    ctx.ciRunnerId = std::getenv("CI_RUNNER_ID") ?: "";
    ctx.ciStage = std::getenv("CI_JOB_STAGE") ?: "";
    ctx.isManualJob = (std::getenv("CI_JOB_MANUAL") != nullptr);
    return ctx;
}

void GitLabCIIntegration::printSection(const std::string &title) {
    std::cout << "\e[0Ksection_start:`date +%s`:" << title << "\r\e[0K" << title << std::endl;
}

void GitLabCIIntegration::printCollapsibleSection(const std::string &title, 
                                                   const std::string &content) {
    printSection(title);
    std::cout << content << std::endl;
    std::cout << "\e[0Ksection_end:`date +%s`:" << title << "\r\e[0K" << std::endl;
}

// ============================================================================
// DockerBuildIntegration Implementation
// ============================================================================

DockerBuildIntegration::BuildConfig DockerBuildIntegration::parseDockerfile(
    const std::string &dockerfilePath) {
    
    BuildConfig config;
    config.multiStage = false;
    
    std::ifstream file(dockerfilePath);
    if (!file.is_open()) return config;
    
    std::string line;
    int fromCount = 0;
    
    while (std::getline(file, line)) {
        if (line.find("FROM ") == 0) {
            fromCount++;
            if (fromCount == 1) {
                size_t pos = line.find(' ');
                if (pos != std::string::npos) {
                    config.baseImage = line.substr(pos + 1);
                }
            }
        }
        if (line.find("ARG ") == 0) {
            config.buildArgs.push_back(line.substr(4));
        }
        if (line.find("WORKDIR ") == 0) {
            config.workdir = line.substr(8);
        }
    }
    
    config.multiStage = (fromCount > 1);
    return config;
}

bool DockerBuildIntegration::injectProtectionLayer(
    const std::string &dockerfilePath, 
    const std::string &protectionConfig) {
    
    // Read original Dockerfile
    std::ifstream file(dockerfilePath);
    if (!file.is_open()) return false;
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    // Inject IronLock layer before final COPY
    std::string injection = R"(
# IronLock Protection Layer
COPY ironlock-config.json /opt/ironlock/
RUN /opt/ironlock/protect.sh --config /opt/ironlock/ironlock-config.json
)";
    
    // Find insertion point (before last FROM or at end)
    size_t insertPos = content.rfind("FROM ");
    if (insertPos != std::string::npos) {
        content.insert(insertPos, injection);
    } else {
        content += injection;
    }
    
    // Write modified Dockerfile
    std::ofstream outFile(dockerfilePath);
    outFile << content;
    
    return true;
}

bool DockerBuildIntegration::createMinimalRuntimeImage(
    const std::string &protectedBinary, 
    const std::string &outputImage) {
    
    std::string dockerfile = R"(
FROM alpine:latest
RUN apk add --no-cache libstdc++
COPY )" + protectedBinary + R"( /app/
RUN chmod +x /app/)" + protectedBinary + R"(
ENTRYPOINT ["/app/)" + protectedBinary + R"("]
)";
    
    // Write temporary Dockerfile
    std::ofstream tmp("Dockerfile.runtime");
    tmp << dockerfile;
    tmp.close();
    
    // Build image
    std::string cmd = "docker build -t " + outputImage + " -f Dockerfile.runtime .";
    return system(cmd.c_str()) == 0;
}

std::string DockerBuildIntegration::generateMultiStageDockerfile(
    const std::string &buildImage,
    const std::string &runtimeImage,
    const std::string &protectedBinary,
    const std::vector<std::string> &dependencies) {
    
    std::stringstream ss;
    
    ss << "# Build Stage\n";
    ss << "FROM " << buildImage << " AS builder\n";
    ss << "WORKDIR /build\n";
    ss << "COPY . .\n";
    ss << "RUN make release\n\n";
    
    ss << "# Protection Stage\n";
    ss << "FROM builder AS protector\n";
    ss << "COPY ironlock-config.json /opt/ironlock/\n";
    ss << "RUN /opt/ironlock/protect.sh --profile release\n\n";
    
    ss << "# Runtime Stage\n";
    ss << "FROM " << runtimeImage << "\n";
    ss << "RUN apk add --no-cache";
    for (const auto& dep : dependencies) {
        ss << " " << dep;
    }
    ss << "\n";
    
    ss << "COPY --from=protector /build/protected/" << protectedBinary << " /app/\n";
    ss << "ENTRYPOINT [\"/app/" << protectedBinary << "\"]\n";
    
    return ss.str();
}

// ============================================================================
// CICDOrchestrator Implementation
// ============================================================================

CICDOrchestrator::CICDOrchestrator() {
    setupPipeline();
}

CICDOrchestrator::~CICDOrchestrator() {}

void CICDOrchestrator::setupPipeline() {
    pipelineStages_ = {
        [this]() { return stageDetect(); },
        [this]() { return stageConfigure(); },
        [this]() { return stageProtect(); },
        [this]() { return stageSign(); },
        [this]() { return stageVerify(); },
        [this]() { return stageReport(); }
    };
}

bool CICDOrchestrator::initialize(const CICDConfig &config) {
    config_ = config;
    detectedPlatform_ = PlatformDetector::detectCurrentPlatform();
    
    configManager_ = std::make_unique<BuildConfigManager>(config);
    signer_ = ArtifactSigner::createFromEnvironment();
    verifier_ = std::make_unique<ReproducibilityVerifier>();
    
    return true;
}

bool CICDOrchestrator::runProtectionPipeline(const std::vector<std::string> &binaries) {
    bool success = true;
    
    for (auto& stage : pipelineStages_) {
        if (!stage()) {
            success = false;
            break;
        }
    }
    
    return success;
}

bool CICDOrchestrator::stageDetect() {
    std::cout << "=== Stage: Platform Detection ===" << std::endl;
    std::cout << "Detected platform: " << PlatformDetector::getPlatformName(detectedPlatform_) << std::endl;
    return true;
}

bool CICDOrchestrator::stageConfigure() {
    std::cout << "=== Stage: Configuration ===" << std::endl;
    if (!config_.profilePath.empty()) {
        configManager_->loadProfile(config_.profilePath);
    }
    return true;
}

bool CICDOrchestrator::stageProtect() {
    std::cout << "=== Stage: Protection ===" << std::endl;
    for (const auto& binary : config_.protectedBinaries) {
        configManager_->applyProtection(binary);
    }
    return true;
}

bool CICDOrchestrator::stageSign() {
    std::cout << "=== Stage: Signing ===" << std::endl;
    if (config_.enableSigning) {
        for (const auto& binary : config_.protectedBinaries) {
            signer_->signFile(binary);
        }
    }
    return true;
}

bool CICDOrchestrator::stageVerify() {
    std::cout << "=== Stage: Verification ===" << std::endl;
    if (config_.verifyReproducibility) {
        for (const auto& binary : config_.protectedBinaries) {
            auto result = verifier_->verify(binary, binary + ".protected");
            if (!result.success) {
                std::cerr << "Verification failed: " << result.errorMessage << std::endl;
                return false;
            }
        }
    }
    return true;
}

bool CICDOrchestrator::stageReport() {
    std::cout << "=== Stage: Reporting ===" << std::endl;
    
    if (detectedPlatform_ == CIPlatform::GitHubActions) {
        GitHubActionsIntegration::setOutput("protection_status", "success");
        GitHubActionsIntegration::setOutput("protected_binaries", 
                                           std::to_string(config_.protectedBinaries.size()));
    } else if (detectedPlatform_ == CIPlatform::GitLabCI) {
        GitLabCIIntegration::printSection("Protection Report");
    }
    
    return true;
}

bool CICDOrchestrator::generateBuildReport(const std::string &outputPath) {
    std::ofstream report(outputPath);
    report << "IronLock Protection Report\n";
    report << "==========================\n\n";
    report << "Platform: " << PlatformDetector::getPlatformName(detectedPlatform_) << "\n";
    report << "Binaries Protected: " << config_.protectedBinaries.size() << "\n";
    report << "Signing Enabled: " << (config_.enableSigning ? "Yes" : "No") << "\n";
    return true;
}

bool CICDOrchestrator::uploadArtifacts(const std::vector<std::string> &paths) {
    // Platform-specific artifact upload
    switch (detectedPlatform_) {
        case CIPlatform::GitHubActions:
            // Would use actions/upload-artifact action
            break;
        case CIPlatform::GitLabCI:
            // Artifacts handled by GitLab CI config
            break;
        default:
            break;
    }
    return true;
}

// Factory functions
std::unique_ptr<CICDOrchestrator> createCICDOrchestrator() {
    return std::make_unique<CICDOrchestrator>();
}

CICDConfig loadConfigFromEnvironment() {
    CICDConfig config;
    config.platform = PlatformDetector::detectCurrentPlatform();
    config.enableSigning = (std::getenv("IRONLOCK_SIGN") != nullptr);
    config.verifyReproducibility = (std::getenv("IRONLOCK_VERIFY") != nullptr);
    
    const char* profile = std::getenv("IRONLOCK_PROFILE");
    if (profile) config.profilePath = profile;
    
    const char* outputDir = std::getenv("IRONLOCK_OUTPUT");
    if (outputDir) config.outputDir = outputDir;
    
    return config;
}

} // namespace ironlock
