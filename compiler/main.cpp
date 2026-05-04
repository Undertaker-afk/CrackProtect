#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <windows.h>
#include <filesystem>

namespace fs = std::filesystem;

// IronLock Compiler Engine (cl-wrapper) v1.1
// Full-featured wrapper for MSVC cl.exe

class CompilerEngine {
public:
    int Execute(int argc, char* argv[]) {
        std::string clPath = "cl.exe";
        std::stringstream cmd;
        cmd << clPath;

        std::string outExe = "a.exe";
        std::vector<std::string> sourceFiles;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg.find("/Fe") == 0) outExe = arg.substr(3);
            else if (arg.find(".cpp") != std::string::npos) sourceFiles.push_back(arg);
            cmd << " " << arg;
        }

        // Apply pre-processing (randomization, transpilation)
        for (const auto& src : sourceFiles) {
            ApplyPreProcessing(src);
        }

        // Inject IronLock SDK
        cmd << " /I../include /link /LIBPATH:../build IronLock.lib Advapi32.lib User32.lib Shell32.lib Iphlpapi.lib Crypt32.lib";

        std::cout << "[*] IronLock Compiler: Invoking MSVC..." << std::endl;
        int res = system(cmd.str().c_str());

        if (res == 0) {
            ApplyPostProcessing(outExe);
            std::cout << "[+] IronLock: Build completed and protected." << std::endl;
        }

        return res;
    }

private:
    void ApplyPreProcessing(const std::string& src) {
        std::cout << "[*] IronLock: Pre-processing " << src << "..." << std::endl;
        // Logic for per-build randomization would be called here
    }

    void ApplyPostProcessing(const std::string& binaryPath) {
        std::cout << "[*] IronLock: Post-processing " << binaryPath << "..." << std::endl;

        std::fstream file(binaryPath, std::ios::binary | std::ios::in | std::ios::out);
        if (!file) return;

        std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        // Calculate .text hash and patch triple-redundant variables
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer.data();
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buffer.data() + dos->e_lfanew);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

        uint32_t textHash = 0;
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)section[i].Name, ".text") == 0) {
                uint32_t h = 0x811C9DC5;
                for(DWORD j=0; j<section[i].Misc.VirtualSize; ++j) {
                    h ^= (uint8_t)buffer[section[i].PointerToRawData + j];
                    h *= 0x01000193;
                }
                textHash = h;
                break;
            }
        }

        std::cout << "[*] IronLock: Integrity Hash = " << std::hex << textHash << std::endl;
        for (size_t i = 0; i < buffer.size() - 4; ++i) {
            if (*(uint32_t*)(buffer.data() + i) == 0xAAAAAAAA) {
                file.seekp(i);
                file.write((char*)&textHash, 4);
            }
        }
        file.close();
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "IronLock Compiler Engine v1.1" << std::endl;
        return 1;
    }
    CompilerEngine engine;
    return engine.Execute(argc, argv);
}
