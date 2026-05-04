#pragma once
#include "IR.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <array>
#include <optional>

namespace IronLock::Modules::VM::Lifter {

// Comprehensive x86/x64 instruction decoder using manual decoding
// This replaces the simplistic decoder with full semantic lifting

enum class InstrCategory : uint8_t {
    NONE, MOV, ARITH, LOGIC, SHIFT_ROTATE, 
    CONTROL_FLOW, STRING, SSE, AVX, FP, 
    SYSTEM, MISC
};

struct X86DecoderContext {
    const uint8_t* code = nullptr;
    size_t size = 0;
    size_t offset = 0;
    uint64_t baseAddress = 0;
    Architecture arch = Architecture::X64;
    
    bool is64Bit() const { return arch == Architecture::X64; }
    uint8_t peekByte() const { return offset < size ? code[offset] : 0; }
    uint8_t readByte() { return offset < size ? code[offset++] : 0; }
    uint32_t readU32() { 
        if (offset + 4 > size) return 0;
        uint32_t v; 
        std::memcpy(&v, code + offset, 4); 
        offset += 4; 
        return v; 
    }
    int32_t readI32() { return static_cast<int32_t>(readU32()); }
    int8_t readI8() { return static_cast<int8_t>(readByte()); }
};

struct ModRM {
    uint8_t mod : 2;
    uint8_t reg : 3;
    uint8_t rm : 3;
};

struct SIB {
    uint8_t scale : 2;
    uint8_t index : 3;
    uint8_t base : 3;
};

class FullX86Lifter {
public:
    static std::vector<DecodedInstruction> DecodeFull(const uint8_t* code, size_t size, 
                                                       uint64_t baseAddress, Architecture arch);
    
private:
    static DecodedInstruction DecodeInstruction(X86DecoderContext& ctx);
    static void ParsePrefixes(X86DecoderContext& ctx, uint32_t& prefixes);
    static void ParseModRM(X86DecoderContext& ctx, ModRM& modrm);
    static void ParseSIB(X86DecoderContext& ctx, SIB& sib);
    static Operand DecodeMemoryOperand(X86DecoderContext& ctx, const ModRM& modrm, uint8_t addrSize);
    static RegisterId DecodeGPR(X86DecoderContext& ctx, uint8_t reg, uint8_t rex_b);
    static void LiftMOV(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode, ModRM& modrm);
    static void LiftARITH(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode, ModRM& modrm);
    static void LiftLOGIC(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode, ModRM& modrm);
    static void LiftSHIFT(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode, ModRM& modrm);
    static void LiftCONTROLFLOW(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode);
    static void LiftSTRING(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode);
    static void LiftPUSHPOP(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode);
    static void LiftCALLRET(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode);
    static void LiftLEA(DecodedInstruction& inst, X86DecoderContext& ctx, ModRM& modrm);
    static void LiftCMP(DecodedInstruction& inst, X86DecoderContext& ctx, ModRM& modrm);
    static void LiftTEST(DecodedInstruction& inst, X86DecoderContext& ctx, ModRM& modrm);
    static void LiftINCDEC(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode, ModRM& modrm);
    static void LiftMULDIV(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode, ModRM& modrm);
    static void LiftJMP(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode);
    static void LiftConditionalJMP(DecodedInstruction& inst, X86DecoderContext& ctx, uint8_t opcode);
    static void LiftSETCC(DecodedInstruction& inst, X86DecoderContext& ctx, ModRM& modrm, uint8_t condition);
    static void LiftCMOV(DecodedInstruction& inst, X86DecoderContext& ctx, ModRM& modrm, uint8_t condition);
    static void LiftXCHG(DecodedInstruction& inst, X86DecoderContext& ctx, ModRM& modrm);
    static void LiftNOP(DecodedInstruction& inst);
    static void LiftCPUID(DecodedInstruction& inst);
    static void LiftSYSCALL(DecodedInstruction& inst);
    static void LiftINT(DecodedInstruction& inst, uint8_t vector);
    static void LiftRDTSC(DecodedInstruction& inst);
    static void LiftCLFLUSH(DecodedInstruction& inst, ModRM& modrm);
    static void LiftPrefetch(DecodedInstruction& inst, ModRM& modrm, uint8_t hint);
};

} // namespace IronLock::Modules::VM::Lifter
