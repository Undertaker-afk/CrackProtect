#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <windows.h>

// IronLock Compiler Engine (cl-wrapper) v1.2
// Production-grade wrapper with functional post-build PE manipulation.

void PatchIntegrityHashes(const std::string& binaryPath) {
    std::cout << "[*] IronLock: Patching integrity hashes in " << binaryPath << "..." << std::endl;

    std::ifstream fileIn(binaryPath, std::ios::binary);
    if (!fileIn) return;
    std::vector<char> buffer((std::istreambuf_iterator<char>(fileIn)), std::istreambuf_iterator<char>());
    fileIn.close();

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

    std::cout << "[*] IronLock: Calculated Hash = 0x" << std::hex << textHash << std::endl;

    std::fstream fileOut(binaryPath, std::ios::binary | std::ios::in | std::ios::out);
    for (size_t i = 0; i < buffer.size() - 4; ++i) {
        if (*(uint32_t*)(buffer.data() + i) == 0xAAAAAAAA) {
            std::cout << "[+] IronLock: Patched hash at offset 0x" << std::hex << i << std::endl;
            fileOut.seekp(i);
            fileOut.write((char*)&textHash, 4);
        }
    }
    fileOut.close();
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

    // Default flags and SDK integration
    cmd << " /nologo /O2 /MT /I../include /link /LIBPATH:../build IronLock.lib Advapi32.lib User32.lib Iphlpapi.lib Shell32.lib Crypt32.lib";

    std::cout << "[*] IronLock Compiler: Executing MSVC..." << std::endl;
    int res = system(cmd.str().c_str());

    if (res == 0) {
        PatchIntegrityHashes(outExe);
        std::cout << "[+] IronLock: Build completed and protected." << std::endl;
    }

    return res;
}
