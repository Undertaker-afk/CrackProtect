#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

namespace IronLock::Modules::VM {

class VirtualMachine {
public:
    enum class OpcodeFamily : uint8_t { ALU, BITWISE, MEMORY, STACK, BRANCH, CALL, SYS_HELPER, CRYPTO_HELPER, META };

    enum class CanonicalOp : uint8_t {
        NOP = 0x00,
        PUSH_IMM64,
        POP,
        DUP,
        ADD,
        SUB,
        MUL,
        DIV,
        MOD,
        AND,
        OR,
        XOR,
        SHL,
        SHR,
        LOAD,
        STORE,
        CMP_EQ,
        CMP_NE,
        CMP_GT,
        CMP_LT,
        JMP,
        JZ,
        JNZ,
        CALL,
        RET,
        SYS_TICK,
        SYS_BRANCH,
        CRYPTO_MIX,
        HALT,
        COUNT
    };

    struct RuntimeProfile {
        std::array<uint8_t, static_cast<size_t>(CanonicalOp::COUNT)> decodeTable{};
        std::array<uint64_t, 4> keySalt{};
        std::array<uint8_t, 32> handlerHash{};
    };

    struct EncryptedProgram {
        uint32_t magic = 0x564D5052;
        uint16_t version = 1;
        uint16_t flags = 0;
        uint64_t nonce = 0;
        std::vector<uint8_t> cipherText;
    };

    static bool InitializeRuntime(const RuntimeProfile& profile);
    static uint64_t Execute(const EncryptedProgram& program);

private:
    struct FlagsRegister { bool zf = false; bool cf = false; bool of = false; bool sf = false; };
    struct VMContext {
        std::array<uint64_t, 16> vregs{};
        std::array<uint64_t, 512> stack{};
        std::array<uint64_t, 4096> memory{};
        std::array<uint32_t, 512> callStack{};
        FlagsRegister flags{};
        uint16_t sp = 0;
        uint16_t csp = 0;
        uint32_t pc = 0;
        bool halted = false;

        bool Push(uint64_t value);
        bool Pop(uint64_t& value);
        bool Peek(uint64_t& value) const;
        uint64_t ReadMem(uint64_t addr) const;
        void WriteMem(uint64_t addr, uint64_t value);
    };

    struct HandlerDesc {
        CanonicalOp op;
        OpcodeFamily family;
        const char* name;
        bool (*fn)(VMContext&, const std::vector<uint8_t>&);
    };

    using HandlerFn = bool (*)(VMContext&, const std::vector<uint8_t>&);

    static std::vector<uint8_t> DecryptProgram(const EncryptedProgram& program);
    static uint64_t DeriveKeyMaterial(const EncryptedProgram& program);
    static bool VerifyHandlerTable();
    static void DispatchNoise(uint32_t pcSeed);
    static uint8_t NextEncodedOpcode(const std::vector<uint8_t>& bytecode, VMContext& ctx, uint64_t rollingKey);

    static void RegisterHandlers();
    static bool RegisterHandler(const HandlerDesc& desc);

    static bool H_Nop(VMContext&, const std::vector<uint8_t>&);
    static bool H_PushImm64(VMContext&, const std::vector<uint8_t>&);
    static bool H_Pop(VMContext&, const std::vector<uint8_t>&);
    static bool H_Dup(VMContext&, const std::vector<uint8_t>&);
    static bool H_BinArith(VMContext&, const std::vector<uint8_t>&, CanonicalOp);
    static bool H_BinBitwise(VMContext&, const std::vector<uint8_t>&, CanonicalOp);
    static bool H_Load(VMContext&, const std::vector<uint8_t>&);
    static bool H_Store(VMContext&, const std::vector<uint8_t>&);
    static bool H_Cmp(VMContext&, const std::vector<uint8_t>&, CanonicalOp);
    static bool H_Jump(VMContext&, const std::vector<uint8_t>&, CanonicalOp);
    static bool H_Call(VMContext&, const std::vector<uint8_t>&);
    static bool H_Ret(VMContext&, const std::vector<uint8_t>&);
    static bool H_SysTick(VMContext&, const std::vector<uint8_t>&);
    static bool H_SysBranch(VMContext&, const std::vector<uint8_t>&);
    static bool H_CryptoMix(VMContext&, const std::vector<uint8_t>&);
    static bool H_Halt(VMContext&, const std::vector<uint8_t>&);
    static bool H_JunkA(VMContext&, const std::vector<uint8_t>&);
    static bool H_JunkB(VMContext&, const std::vector<uint8_t>&);

    static std::array<uint8_t, 256> s_DecodeLut;
    static std::array<HandlerFn, static_cast<size_t>(CanonicalOp::COUNT)> s_Handlers;
    static std::array<uint8_t, 32> s_ExpectedHandlerHash;
    static std::array<uint64_t, 4> s_KeySalt;
    static std::array<uint8_t, static_cast<size_t>(CanonicalOp::COUNT)> s_OpRemap;
    static std::array<HandlerFn, 8> s_JunkHandlers;
    static std::atomic<uint32_t> s_DispatchCounter;
    static std::mutex s_InitLock;
    static bool s_Initialized;
};

} // namespace IronLock::Modules::VM
