#include "VirtualMachine.h"

#include <chrono>
#include <cstring>
#include <functional>
#include <random>

namespace IronLock::Modules::VM {

std::array<uint8_t, 256> VirtualMachine::s_DecodeLut{};
std::array<VirtualMachine::HandlerFn, static_cast<size_t>(VirtualMachine::CanonicalOp::COUNT)> VirtualMachine::s_Handlers{};
std::array<uint8_t, 32> VirtualMachine::s_ExpectedHandlerHash{};
std::array<uint64_t, 4> VirtualMachine::s_KeySalt{};
std::atomic<uint32_t> VirtualMachine::s_DispatchCounter{0};
std::mutex VirtualMachine::s_InitLock;
bool VirtualMachine::s_Initialized = false;

namespace {
uint64_t ReadU64(const std::vector<uint8_t>& bc, uint32_t& pc) {
    if (pc + 8 > bc.size()) return 0;
    uint64_t v = 0;
    std::memcpy(&v, bc.data() + pc, 8);
    pc += 8;
    return v;
}

int32_t ReadI32(const std::vector<uint8_t>& bc, uint32_t& pc) {
    if (pc + 4 > bc.size()) return 0;
    int32_t v = 0;
    std::memcpy(&v, bc.data() + pc, 4);
    pc += 4;
    return v;
}
} // namespace

bool VirtualMachine::InitializeRuntime(const RuntimeProfile& profile) {
    std::lock_guard<std::mutex> lock(s_InitLock);
    std::fill(s_DecodeLut.begin(), s_DecodeLut.end(), static_cast<uint8_t>(CanonicalOp::HALT));
    for (size_t i = 0; i < profile.decodeTable.size(); ++i) {
        s_DecodeLut[profile.decodeTable[i]] = static_cast<uint8_t>(i);
    }
    s_ExpectedHandlerHash = profile.handlerHash;
    s_KeySalt = profile.keySalt;

    s_Handlers.fill(nullptr);
    s_Handlers[(size_t)CanonicalOp::NOP] = &H_Nop;
    s_Handlers[(size_t)CanonicalOp::PUSH_IMM64] = &H_PushImm64;
    s_Handlers[(size_t)CanonicalOp::POP] = &H_Pop;
    s_Handlers[(size_t)CanonicalOp::DUP] = &H_Dup;
    s_Handlers[(size_t)CanonicalOp::ADD] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_BinArith(c, b, CanonicalOp::ADD); };
    s_Handlers[(size_t)CanonicalOp::SUB] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_BinArith(c, b, CanonicalOp::SUB); };
    s_Handlers[(size_t)CanonicalOp::MUL] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_BinArith(c, b, CanonicalOp::MUL); };
    s_Handlers[(size_t)CanonicalOp::DIV] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_BinArith(c, b, CanonicalOp::DIV); };
    s_Handlers[(size_t)CanonicalOp::MOD] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_BinArith(c, b, CanonicalOp::MOD); };
    s_Handlers[(size_t)CanonicalOp::AND] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_BinBitwise(c, b, CanonicalOp::AND); };
    s_Handlers[(size_t)CanonicalOp::OR] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_BinBitwise(c, b, CanonicalOp::OR); };
    s_Handlers[(size_t)CanonicalOp::XOR] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_BinBitwise(c, b, CanonicalOp::XOR); };
    s_Handlers[(size_t)CanonicalOp::SHL] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_BinBitwise(c, b, CanonicalOp::SHL); };
    s_Handlers[(size_t)CanonicalOp::SHR] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_BinBitwise(c, b, CanonicalOp::SHR); };
    s_Handlers[(size_t)CanonicalOp::LOAD] = &H_Load;
    s_Handlers[(size_t)CanonicalOp::STORE] = &H_Store;
    s_Handlers[(size_t)CanonicalOp::CMP_EQ] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_Cmp(c, b, CanonicalOp::CMP_EQ); };
    s_Handlers[(size_t)CanonicalOp::CMP_NE] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_Cmp(c, b, CanonicalOp::CMP_NE); };
    s_Handlers[(size_t)CanonicalOp::CMP_GT] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_Cmp(c, b, CanonicalOp::CMP_GT); };
    s_Handlers[(size_t)CanonicalOp::CMP_LT] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_Cmp(c, b, CanonicalOp::CMP_LT); };
    s_Handlers[(size_t)CanonicalOp::JMP] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_Jump(c, b, CanonicalOp::JMP); };
    s_Handlers[(size_t)CanonicalOp::JZ] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_Jump(c, b, CanonicalOp::JZ); };
    s_Handlers[(size_t)CanonicalOp::JNZ] = [](VMContext& c, const std::vector<uint8_t>& b) { return H_Jump(c, b, CanonicalOp::JNZ); };
    s_Handlers[(size_t)CanonicalOp::CALL] = &H_Call;
    s_Handlers[(size_t)CanonicalOp::RET] = &H_Ret;
    s_Handlers[(size_t)CanonicalOp::OPAQUE_TICK] = &H_OpaqueTick;
    s_Handlers[(size_t)CanonicalOp::OPAQUE_BRANCH] = &H_OpaqueBranch;
    s_Handlers[(size_t)CanonicalOp::HALT] = &H_Halt;

    s_Initialized = VerifyHandlerTable();
    return s_Initialized;
}

std::vector<uint8_t> VirtualMachine::DecryptProgram(const EncryptedProgram& program) {
    auto out = program.cipherText;
    uint64_t key = DeriveKeyMaterial(program);
    for (size_t i = 0; i < out.size(); ++i) {
        uint8_t stream = static_cast<uint8_t>((key >> ((i % 8) * 8)) & 0xFF);
        stream ^= static_cast<uint8_t>((i * 131) + (program.nonce & 0xFF));
        out[i] ^= stream;
    }
    return out;
}

uint64_t VirtualMachine::DeriveKeyMaterial(const EncryptedProgram& program) {
    std::hash<std::thread::id> tidHash;
    uint64_t seed = program.nonce ^ 0x9E3779B97F4A7C15ULL;
    seed ^= (uint64_t)tidHash(std::this_thread::get_id());
    for (size_t i = 0; i < s_KeySalt.size(); ++i) {
        seed ^= (s_KeySalt[i] + 0x9E37ULL) << (i * 7);
    }
    return seed;
}

bool VirtualMachine::VerifyHandlerTable() {
    uint64_t h = 1469598103934665603ULL;
    for (auto fn : s_Handlers) {
        uint64_t v = reinterpret_cast<uint64_t>(fn);
        h ^= v;
        h *= 1099511628211ULL;
    }
    std::array<uint8_t, 32> current{};
    for (size_t i = 0; i < current.size(); ++i) {
        current[i] = static_cast<uint8_t>((h >> ((i % 8) * 8)) ^ (i * 17));
    }
    bool strict = false;
    for (auto b : s_ExpectedHandlerHash) { if (b != 0) { strict = true; break; } }
    return strict ? (current == s_ExpectedHandlerHash) : true;
}

void VirtualMachine::DispatchNoise(uint32_t pcSeed) {
    std::mt19937 rng(pcSeed ^ (uint32_t)s_DispatchCounter.load());
    auto spin = rng() % 16;
    for (uint32_t i = 0; i < spin; ++i) {
        (void)std::chrono::high_resolution_clock::now().time_since_epoch().count();
    }
    if ((rng() & 0x7) == 0) {
        std::thread jitter([] { std::this_thread::sleep_for(std::chrono::microseconds(25)); });
        jitter.join();
    }
}

uint64_t VirtualMachine::Execute(const EncryptedProgram& program) {
    if (!s_Initialized || program.magic != 0x564D5052 || !VerifyHandlerTable()) return 0;
    auto bytecode = DecryptProgram(program);
    VMContext ctx{};
    uint32_t periodic = 0;
    while (ctx.pc < bytecode.size() && !ctx.halted) {
        if ((++periodic & 0x3F) == 0 && !VerifyHandlerTable()) return 0;
        DispatchNoise(ctx.pc);

        uint8_t encoded = bytecode[ctx.pc++];
        auto op = static_cast<CanonicalOp>(s_DecodeLut[encoded]);
        auto idx = static_cast<size_t>(op);
        if (idx >= s_Handlers.size() || !s_Handlers[idx] || !s_Handlers[idx](ctx, bytecode)) return 0;
        ++s_DispatchCounter;
    }
    return (ctx.sp > 0) ? ctx.stack[ctx.sp - 1] : 0;
}

bool VirtualMachine::H_Nop(VMContext&, const std::vector<uint8_t>&) { return true; }
bool VirtualMachine::H_PushImm64(VMContext& c, const std::vector<uint8_t>& b) { if (c.sp >= c.stack.size()) return false; c.stack[c.sp++] = ReadU64(b, c.pc); return true; }
bool VirtualMachine::H_Pop(VMContext& c, const std::vector<uint8_t>&) { if (c.sp == 0) return false; --c.sp; return true; }
bool VirtualMachine::H_Dup(VMContext& c, const std::vector<uint8_t>&) { if (c.sp == 0 || c.sp >= c.stack.size()) return false; c.stack[c.sp] = c.stack[c.sp - 1]; ++c.sp; return true; }

bool VirtualMachine::H_BinArith(VMContext& c, const std::vector<uint8_t>&, CanonicalOp op) {
    if (c.sp < 2) return false;
    uint64_t b = c.stack[--c.sp], a = c.stack[--c.sp], r = 0;
    if (op == CanonicalOp::ADD) r = a + b;
    else if (op == CanonicalOp::SUB) r = a - b;
    else if (op == CanonicalOp::MUL) r = a * b;
    else if (op == CanonicalOp::DIV) { if (b == 0) return false; r = a / b; }
    else if (op == CanonicalOp::MOD) { if (b == 0) return false; r = a % b; }
    c.stack[c.sp++] = r;
    return true;
}

bool VirtualMachine::H_BinBitwise(VMContext& c, const std::vector<uint8_t>&, CanonicalOp op) {
    if (c.sp < 2) return false;
    uint64_t b = c.stack[--c.sp], a = c.stack[--c.sp], r = 0;
    if (op == CanonicalOp::AND) r = a & b;
    else if (op == CanonicalOp::OR) r = a | b;
    else if (op == CanonicalOp::XOR) r = a ^ b;
    else if (op == CanonicalOp::SHL) r = a << (b & 0x3F);
    else if (op == CanonicalOp::SHR) r = a >> (b & 0x3F);
    c.stack[c.sp++] = r;
    return true;
}

bool VirtualMachine::H_Load(VMContext& c, const std::vector<uint8_t>&) { if (c.sp == 0) return false; auto addr = c.stack[c.sp - 1] % c.memory.size(); c.stack[c.sp - 1] = c.memory[addr]; return true; }
bool VirtualMachine::H_Store(VMContext& c, const std::vector<uint8_t>&) { if (c.sp < 2) return false; uint64_t v = c.stack[--c.sp]; auto addr = c.stack[--c.sp] % c.memory.size(); c.memory[addr] = v; return true; }

bool VirtualMachine::H_Cmp(VMContext& c, const std::vector<uint8_t>&, CanonicalOp op) {
    if (c.sp < 2) return false;
    uint64_t b = c.stack[--c.sp], a = c.stack[--c.sp];
    if (op == CanonicalOp::CMP_EQ) c.zf = (a == b);
    else if (op == CanonicalOp::CMP_NE) c.zf = (a != b);
    else if (op == CanonicalOp::CMP_GT) c.zf = (a > b);
    else if (op == CanonicalOp::CMP_LT) c.zf = (a < b);
    return true;
}

bool VirtualMachine::H_Jump(VMContext& c, const std::vector<uint8_t>& b, CanonicalOp op) {
    int32_t off = ReadI32(b, c.pc);
    bool take = (op == CanonicalOp::JMP) || (op == CanonicalOp::JZ && c.zf) || (op == CanonicalOp::JNZ && !c.zf);
    if (take) c.pc = static_cast<uint32_t>(static_cast<int64_t>(c.pc) + off);
    return true;
}

bool VirtualMachine::H_Call(VMContext& c, const std::vector<uint8_t>& b) {
    if (c.csp >= c.callStack.size()) return false;
    int32_t off = ReadI32(b, c.pc);
    c.callStack[c.csp++] = c.pc;
    c.pc = static_cast<uint32_t>(static_cast<int64_t>(c.pc) + off);
    return true;
}

bool VirtualMachine::H_Ret(VMContext& c, const std::vector<uint8_t>&) { if (c.csp == 0) { c.halted = true; return true; } c.pc = c.callStack[--c.csp]; return true; }
bool VirtualMachine::H_OpaqueTick(VMContext& c, const std::vector<uint8_t>&) { c.zf = ((c.pc ^ c.sp ^ s_DispatchCounter.load()) & 1) == 0; return true; }
bool VirtualMachine::H_OpaqueBranch(VMContext& c, const std::vector<uint8_t>& b) { int32_t off = ReadI32(b, c.pc); if (((c.pc * 33U) ^ (uint32_t)c.sp) % 7 == 3) c.pc += off; return true; }
bool VirtualMachine::H_Halt(VMContext& c, const std::vector<uint8_t>&) { c.halted = true; return true; }

} // namespace IronLock::Modules::VM
