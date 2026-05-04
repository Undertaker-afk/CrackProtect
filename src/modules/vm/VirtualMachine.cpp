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
std::array<uint8_t, static_cast<size_t>(VirtualMachine::CanonicalOp::COUNT)> VirtualMachine::s_OpRemap{};
std::array<VirtualMachine::HandlerFn, 8> VirtualMachine::s_JunkHandlers{};
std::atomic<uint32_t> VirtualMachine::s_DispatchCounter{0};
std::mutex VirtualMachine::s_InitLock;
bool VirtualMachine::s_Initialized = false;

namespace {
uint64_t ReadU64(const std::vector<uint8_t>& bc, uint32_t& pc) { uint64_t v = 0; if (pc + 8 <= bc.size()) std::memcpy(&v, bc.data() + pc, 8); pc += 8; return v; }
int32_t ReadI32(const std::vector<uint8_t>& bc, uint32_t& pc) { int32_t v = 0; if (pc + 4 <= bc.size()) std::memcpy(&v, bc.data() + pc, 4); pc += 4; return v; }
}

bool VirtualMachine::VMContext::Push(uint64_t value) { if (sp >= stack.size()) return false; stack[sp++] = value; return true; }
bool VirtualMachine::VMContext::Pop(uint64_t& value) { if (sp == 0) return false; value = stack[--sp]; return true; }
bool VirtualMachine::VMContext::Peek(uint64_t& value) const { if (sp == 0) return false; value = stack[sp - 1]; return true; }
uint64_t VirtualMachine::VMContext::ReadMem(uint64_t addr) const { return memory[addr % memory.size()]; }
void VirtualMachine::VMContext::WriteMem(uint64_t addr, uint64_t value) { memory[addr % memory.size()] = value; }

bool VirtualMachine::RegisterHandler(const HandlerDesc& desc) {
    auto idx = static_cast<size_t>(desc.op);
    if (idx >= s_Handlers.size()) return false;
    s_Handlers[idx] = desc.fn;
    return true;
}

void VirtualMachine::RegisterHandlers() {
    s_Handlers.fill(nullptr);
    const HandlerDesc handlers[] = {
        {CanonicalOp::NOP, OpcodeFamily::META, "nop", &H_Nop}, {CanonicalOp::PUSH_IMM64, OpcodeFamily::STACK, "push", &H_PushImm64},
        {CanonicalOp::POP, OpcodeFamily::STACK, "pop", &H_Pop}, {CanonicalOp::DUP, OpcodeFamily::STACK, "dup", &H_Dup},
        {CanonicalOp::ADD, OpcodeFamily::ALU, "add", [](VMContext& c, const std::vector<uint8_t>& b){ return H_BinArith(c,b,CanonicalOp::ADD);} },
        {CanonicalOp::SUB, OpcodeFamily::ALU, "sub", [](VMContext& c, const std::vector<uint8_t>& b){ return H_BinArith(c,b,CanonicalOp::SUB);} },
        {CanonicalOp::MUL, OpcodeFamily::ALU, "mul", [](VMContext& c, const std::vector<uint8_t>& b){ return H_BinArith(c,b,CanonicalOp::MUL);} },
        {CanonicalOp::DIV, OpcodeFamily::ALU, "div", [](VMContext& c, const std::vector<uint8_t>& b){ return H_BinArith(c,b,CanonicalOp::DIV);} },
        {CanonicalOp::MOD, OpcodeFamily::ALU, "mod", [](VMContext& c, const std::vector<uint8_t>& b){ return H_BinArith(c,b,CanonicalOp::MOD);} },
        {CanonicalOp::AND, OpcodeFamily::BITWISE, "and", [](VMContext& c, const std::vector<uint8_t>& b){ return H_BinBitwise(c,b,CanonicalOp::AND);} },
        {CanonicalOp::OR, OpcodeFamily::BITWISE, "or", [](VMContext& c, const std::vector<uint8_t>& b){ return H_BinBitwise(c,b,CanonicalOp::OR);} },
        {CanonicalOp::XOR, OpcodeFamily::BITWISE, "xor", [](VMContext& c, const std::vector<uint8_t>& b){ return H_BinBitwise(c,b,CanonicalOp::XOR);} },
        {CanonicalOp::SHL, OpcodeFamily::BITWISE, "shl", [](VMContext& c, const std::vector<uint8_t>& b){ return H_BinBitwise(c,b,CanonicalOp::SHL);} },
        {CanonicalOp::SHR, OpcodeFamily::BITWISE, "shr", [](VMContext& c, const std::vector<uint8_t>& b){ return H_BinBitwise(c,b,CanonicalOp::SHR);} },
        {CanonicalOp::LOAD, OpcodeFamily::MEMORY, "load", &H_Load}, {CanonicalOp::STORE, OpcodeFamily::MEMORY, "store", &H_Store},
        {CanonicalOp::CMP_EQ, OpcodeFamily::ALU, "cmpeq", [](VMContext& c, const std::vector<uint8_t>& b){ return H_Cmp(c,b,CanonicalOp::CMP_EQ);} },
        {CanonicalOp::CMP_NE, OpcodeFamily::ALU, "cmpne", [](VMContext& c, const std::vector<uint8_t>& b){ return H_Cmp(c,b,CanonicalOp::CMP_NE);} },
        {CanonicalOp::CMP_GT, OpcodeFamily::ALU, "cmpgt", [](VMContext& c, const std::vector<uint8_t>& b){ return H_Cmp(c,b,CanonicalOp::CMP_GT);} },
        {CanonicalOp::CMP_LT, OpcodeFamily::ALU, "cmplt", [](VMContext& c, const std::vector<uint8_t>& b){ return H_Cmp(c,b,CanonicalOp::CMP_LT);} },
        {CanonicalOp::JMP, OpcodeFamily::BRANCH, "jmp", [](VMContext& c, const std::vector<uint8_t>& b){ return H_Jump(c,b,CanonicalOp::JMP);} },
        {CanonicalOp::JZ, OpcodeFamily::BRANCH, "jz", [](VMContext& c, const std::vector<uint8_t>& b){ return H_Jump(c,b,CanonicalOp::JZ);} },
        {CanonicalOp::JNZ, OpcodeFamily::BRANCH, "jnz", [](VMContext& c, const std::vector<uint8_t>& b){ return H_Jump(c,b,CanonicalOp::JNZ);} },
        {CanonicalOp::CALL, OpcodeFamily::CALL, "call", &H_Call}, {CanonicalOp::RET, OpcodeFamily::CALL, "ret", &H_Ret},
        {CanonicalOp::SYS_TICK, OpcodeFamily::SYS_HELPER, "sys_tick", &H_SysTick}, {CanonicalOp::SYS_BRANCH, OpcodeFamily::SYS_HELPER, "sys_branch", &H_SysBranch},
        {CanonicalOp::CRYPTO_MIX, OpcodeFamily::CRYPTO_HELPER, "crypto_mix", &H_CryptoMix}, {CanonicalOp::HALT, OpcodeFamily::META, "halt", &H_Halt},
    };
    for (const auto& h : handlers) RegisterHandler(h);
    s_JunkHandlers = {&H_JunkA, &H_JunkB, &H_JunkA, &H_JunkB, &H_JunkA, &H_JunkB, &H_JunkA, &H_JunkB};
}

bool VirtualMachine::InitializeRuntime(const RuntimeProfile& profile) {
    std::lock_guard<std::mutex> lock(s_InitLock);
    std::fill(s_DecodeLut.begin(), s_DecodeLut.end(), static_cast<uint8_t>(CanonicalOp::HALT));
    for (size_t i = 0; i < profile.decodeTable.size(); ++i) {
        s_DecodeLut[profile.decodeTable[i]] = static_cast<uint8_t>(i);
        s_OpRemap[i] = static_cast<uint8_t>((profile.decodeTable[i] ^ static_cast<uint8_t>(i * 13 + 0x5A)) & 0xFF);
    }
    s_ExpectedHandlerHash = profile.handlerHash;
    s_KeySalt = profile.keySalt;
    RegisterHandlers();
    s_Initialized = VerifyHandlerTable();
    return s_Initialized;
}
std::vector<uint8_t> VirtualMachine::DecryptProgram(const EncryptedProgram& program) { auto out = program.cipherText; uint64_t key = DeriveKeyMaterial(program); for (size_t i = 0; i < out.size(); ++i) { uint8_t stream = static_cast<uint8_t>((key >> ((i % 8) * 8)) & 0xFF); stream ^= static_cast<uint8_t>((i * 131) + (program.nonce & 0xFF)); out[i] ^= stream; } return out; }
uint64_t VirtualMachine::DeriveKeyMaterial(const EncryptedProgram& program) { std::hash<std::thread::id> tidHash; uint64_t seed = program.nonce ^ 0x9E3779B97F4A7C15ULL; seed ^= (uint64_t)tidHash(std::this_thread::get_id()); for (size_t i = 0; i < s_KeySalt.size(); ++i) seed ^= (s_KeySalt[i] + 0x9E37ULL) << (i * 7); return seed; }

uint8_t VirtualMachine::NextEncodedOpcode(const std::vector<uint8_t>& bytecode, VMContext& ctx, uint64_t rollingKey) {
    auto encoded = bytecode[ctx.pc++];
    return static_cast<uint8_t>(encoded ^ static_cast<uint8_t>((rollingKey >> ((ctx.pc + s_DispatchCounter.load()) & 7U) * 8U) & 0xFFU));
}

bool VirtualMachine::VerifyHandlerTable() { uint64_t h = 1469598103934665603ULL; for (auto fn : s_Handlers) { uint64_t v = reinterpret_cast<uint64_t>(fn); h ^= v; h *= 1099511628211ULL; } std::array<uint8_t, 32> current{}; for (size_t i = 0; i < current.size(); ++i) current[i] = static_cast<uint8_t>((h >> ((i % 8) * 8)) ^ (i * 17)); bool strict = false; for (auto b : s_ExpectedHandlerHash) if (b != 0) { strict = true; break; } return strict ? (current == s_ExpectedHandlerHash) : true; }
void VirtualMachine::DispatchNoise(uint32_t pcSeed) { std::mt19937 rng(pcSeed ^ (uint32_t)s_DispatchCounter.load()); auto spin = rng() % 16; for (uint32_t i = 0; i < spin; ++i) (void)std::chrono::high_resolution_clock::now().time_since_epoch().count(); if ((rng() & 0x3) == 0) { VMContext junk{}; auto h = s_JunkHandlers[rng() % s_JunkHandlers.size()]; h(junk, {}); } }

uint64_t VirtualMachine::Execute(const EncryptedProgram& program) {
    if (!s_Initialized || program.magic != 0x564D5052 || !VerifyHandlerTable()) return 0;
    auto bytecode = DecryptProgram(program);
    VMContext ctx{};
    const auto rollingKey = DeriveKeyMaterial(program) ^ program.nonce;
    uint32_t periodic = 0;
    while (ctx.pc < bytecode.size() && !ctx.halted) {
        if ((++periodic & 0x3F) == 0 && !VerifyHandlerTable()) return 0;
        DispatchNoise(ctx.pc);
        auto encoded = NextEncodedOpcode(bytecode, ctx, rollingKey);
        auto op = static_cast<CanonicalOp>(s_DecodeLut[encoded]);
        auto idx = static_cast<size_t>(op);
        if (idx >= s_Handlers.size() || !s_Handlers[idx] || !s_Handlers[idx](ctx, bytecode)) return 0;
        if ((s_DispatchCounter.load() & 0x0F) == 7) { uint32_t bogus = (ctx.pc * 1103515245U + 12345U); if ((bogus & 0x1F) == 0x11) ctx.vregs[0] ^= bogus; }
        ++s_DispatchCounter;
    }
    return (ctx.sp > 0) ? ctx.stack[ctx.sp - 1] : ctx.vregs[0];
}

bool VirtualMachine::H_Nop(VMContext&, const std::vector<uint8_t>&) { return true; }
bool VirtualMachine::H_PushImm64(VMContext& c, const std::vector<uint8_t>& b) { return c.Push(ReadU64(b, c.pc)); }
bool VirtualMachine::H_Pop(VMContext& c, const std::vector<uint8_t>&) { uint64_t discard = 0; return c.Pop(discard); }
bool VirtualMachine::H_Dup(VMContext& c, const std::vector<uint8_t>&) { uint64_t v = 0; return c.Peek(v) && c.Push(v); }

bool VirtualMachine::H_BinArith(VMContext& c, const std::vector<uint8_t>&, CanonicalOp op) { uint64_t b=0,a=0,r=0; if (!c.Pop(b) || !c.Pop(a)) return false; if (op == CanonicalOp::ADD) r=a+b; else if (op == CanonicalOp::SUB) r=a-b; else if (op == CanonicalOp::MUL) r=a*b; else if (op == CanonicalOp::DIV) { if (!b) return false; r=a/b; } else if (op == CanonicalOp::MOD) { if (!b) return false; r=a%b; } c.flags.zf = (r == 0); c.flags.sf = (r >> 63) != 0; c.vregs[0] = r; return c.Push(r); }
bool VirtualMachine::H_BinBitwise(VMContext& c, const std::vector<uint8_t>&, CanonicalOp op) { uint64_t b=0,a=0,r=0; if (!c.Pop(b) || !c.Pop(a)) return false; if (op == CanonicalOp::AND) r=a&b; else if (op == CanonicalOp::OR) r=a|b; else if (op == CanonicalOp::XOR) r=a^b; else if (op == CanonicalOp::SHL) r=a<<(b&0x3F); else if (op == CanonicalOp::SHR) r=a>>(b&0x3F); c.vregs[1] = r; return c.Push(r); }
bool VirtualMachine::H_Load(VMContext& c, const std::vector<uint8_t>&) { uint64_t addr = 0; if (!c.Peek(addr)) return false; c.stack[c.sp - 1] = c.ReadMem(addr); return true; }
bool VirtualMachine::H_Store(VMContext& c, const std::vector<uint8_t>&) { uint64_t v=0, addr=0; if (!c.Pop(v) || !c.Pop(addr)) return false; c.WriteMem(addr, v); return true; }
bool VirtualMachine::H_Cmp(VMContext& c, const std::vector<uint8_t>&, CanonicalOp op) { uint64_t b=0,a=0; if (!c.Pop(b) || !c.Pop(a)) return false; if (op == CanonicalOp::CMP_EQ) c.flags.zf = (a == b); else if (op == CanonicalOp::CMP_NE) c.flags.zf = (a != b); else if (op == CanonicalOp::CMP_GT) c.flags.zf = (a > b); else if (op == CanonicalOp::CMP_LT) c.flags.zf = (a < b); return true; }
bool VirtualMachine::H_Jump(VMContext& c, const std::vector<uint8_t>& b, CanonicalOp op) { int32_t off = ReadI32(b, c.pc); bool take = (op == CanonicalOp::JMP) || (op == CanonicalOp::JZ && c.flags.zf) || (op == CanonicalOp::JNZ && !c.flags.zf); if (take) c.pc = static_cast<uint32_t>(static_cast<int64_t>(c.pc) + off); return true; }
bool VirtualMachine::H_Call(VMContext& c, const std::vector<uint8_t>& b) { if (c.csp >= c.callStack.size()) return false; int32_t off = ReadI32(b, c.pc); c.callStack[c.csp++] = c.pc; c.pc = static_cast<uint32_t>(static_cast<int64_t>(c.pc) + off); return true; }
bool VirtualMachine::H_Ret(VMContext& c, const std::vector<uint8_t>&) { if (c.csp == 0) { c.halted = true; return true; } c.pc = c.callStack[--c.csp]; return true; }
bool VirtualMachine::H_SysTick(VMContext& c, const std::vector<uint8_t>&) { c.flags.zf = ((c.pc ^ c.sp ^ s_DispatchCounter.load()) & 1) == 0; return true; }
bool VirtualMachine::H_SysBranch(VMContext& c, const std::vector<uint8_t>& b) { int32_t off = ReadI32(b, c.pc); if (((c.pc * 33U) ^ (uint32_t)c.sp) % 7 == 3) c.pc += off; return true; }
bool VirtualMachine::H_CryptoMix(VMContext& c, const std::vector<uint8_t>&) { c.vregs[2] = (c.vregs[0] << 7) ^ (c.vregs[1] >> 3) ^ (c.vregs[2] + 0x9E3779B97F4A7C15ULL); c.flags.cf = (c.vregs[2] & 1) != 0; return true; }
bool VirtualMachine::H_Halt(VMContext& c, const std::vector<uint8_t>&) { c.halted = true; return true; }
bool VirtualMachine::H_JunkA(VMContext& c, const std::vector<uint8_t>&) { c.vregs[7] ^= (c.pc * 2654435761U); return true; }
bool VirtualMachine::H_JunkB(VMContext& c, const std::vector<uint8_t>&) { c.flags.of = ((c.vregs[7] + c.sp) & 4) != 0; return true; }

} // namespace IronLock::Modules::VM
