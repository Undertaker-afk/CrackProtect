#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <windows.h>

// IronLock Compiler Engine (cl-wrapper) v1.0
// Transparently passes flags to MSVC while integrating IronLock protections.

void PostProcess(const std::string& binaryPath) {
    std::cout << "[*] IronLock: Post-processing " << binaryPath << "..." << std::endl;

    std::fstream file(binaryPath, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) return;

    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // 1. Calculate .text section hash
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer.data();
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buffer.data() + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    uint32_t textHash = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            // Simple FNV-1a for demonstration in post-processor
            uint32_t h = 0x811C9DC5;
            for(DWORD j=0; j<section[i].Misc.VirtualSize; ++j) {
                h ^= (uint8_t)buffer[section[i].PointerToRawData + j];
                h *= 0x01000193;
            }
            textHash = h;
            break;
        }
    }

    // 2. Patch triple-redundant variables (Search for 0xAAAAAAAA)
    std::cout << "[*] Patching integrity hash: " << std::hex << textHash << std::endl;
    for (size_t i = 0; i < buffer.size() - 4; ++i) {
        if (*(uint32_t*)(buffer.data() + i) == 0xAAAAAAAA) {
            file.seekp(i);
            file.write((char*)&textHash, 4);
        }
    }
    file.close();
}

int main(int argc, char* argv[]) {
    std::stringstream cmd;
    cmd << "cl.exe";

    std::string outExe = "a.exe";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.find("/Fe") == 0) outExe = arg.substr(3);
        cmd << " " << arg;
    }

    cmd << " /I../include /link /LIBPATH:../build IronLock.lib Advapi32.lib User32.lib Shell32.lib Iphlpapi.lib Crypt32.lib";

    std::cout << "[*] IronLock Compiler: " << cmd.str() << std::endl;
    int res = system(cmd.str().c_str());

    if (res == 0) {
        PostProcess(outExe);
        std::cout << "[+] IronLock: Build completed and protected." << std::endl;
    }

    return res;
}
