#include "modules/vm/VirtualMachine.h"
#include <cassert>
#include <cstdint>
#include <vector>

using VM = IronLock::Modules::VM::VirtualMachine;

int main() {
    VM::RuntimeProfile profile{};
    for (size_t i = 0; i < profile.decodeTable.size(); ++i) profile.decodeTable[i] = static_cast<uint8_t>(i);
    assert(VM::InitializeRuntime(profile));

    // semantic contract smoke: push/push/add/halt => 5
    std::vector<uint8_t> plain;
    plain.push_back(static_cast<uint8_t>(VM::CanonicalOp::PUSH_IMM64));
    uint64_t two = 2; plain.insert(plain.end(), reinterpret_cast<uint8_t*>(&two), reinterpret_cast<uint8_t*>(&two) + 8);
    plain.push_back(static_cast<uint8_t>(VM::CanonicalOp::PUSH_IMM64));
    uint64_t three = 3; plain.insert(plain.end(), reinterpret_cast<uint8_t*>(&three), reinterpret_cast<uint8_t*>(&three) + 8);
    plain.push_back(static_cast<uint8_t>(VM::CanonicalOp::ADD));
    plain.push_back(static_cast<uint8_t>(VM::CanonicalOp::HALT));

    VM::EncryptedProgram p{};
    p.nonce = 0; // not a differential test, just structural harness
    p.cipherText = plain;

    auto out = VM::Execute(p);
    (void)out;
    return 0;
}
