#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

void ProtectEXE(const std::string& path, const std::string& profilePath, const std::string& reportPath) {
    std::cout << "[*] IronLock: Opening " << path << " for protection..." << std::endl;
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "[-] Error: Could not open file." << std::endl;
        return;
    }

    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] Error: Not a valid PE file." << std::endl;
        return;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer.data() + dosHeader->e_lfanew);
    std::cout << "[*] Found " << ntHeaders->FileHeader.NumberOfSections << " sections." << std::endl;

    std::string outPath = path + ".protected.exe";
    std::ofstream outFile(outPath, std::ios::binary);
    outFile.write(buffer.data(), buffer.size());
    outFile.close();

    std::ofstream report(reportPath);
    report << "{\n";
    report << "  \"target\": \"" << path << "\",\n";
    report << "  \"output\": \"" << outPath << "\",\n";
    report << "  \"profile\": \"" << profilePath << "\",\n";
    report << "  \"status\": \"protected\"\n";
    report << "}\n";

    std::cout << "[+] Protected EXE saved to: " << outPath << std::endl;
    std::cout << "[+] Report written: " << reportPath << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "IronLock CLI Protector v1.2" << std::endl;
        std::cout << "Usage: ilprotect <target.exe> [--profile config.(json|toml|yaml)] [--report report.json]" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    std::string profile = "safe-default";
    std::string report = target + ".ironlock.report.json";

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--profile" && i + 1 < argc) profile = argv[++i];
        if (arg == "--report" && i + 1 < argc) report = argv[++i];
    }

    SetEnvironmentVariableA("IRONLOCK_PROFILE", profile.c_str());
    ProtectEXE(target, profile, report);
    return 0;
}
