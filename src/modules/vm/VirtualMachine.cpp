#include "VirtualMachine.h"

namespace IronLock::Modules::VM {

uint64_t VirtualMachine::Execute(const std::vector<uint8_t>& bytecode) {
    VMContext ctx;
    ctx.sp = 0;
    ctx.pc = 0;

    while (ctx.pc < bytecode.size()) {
        OpCode op = static_cast<OpCode>(bytecode[ctx.pc++]);
        switch (op) {
            case OpCode::OP_PUSH: {
                uint16_t val = bytecode[ctx.pc] | (bytecode[ctx.pc + 1] << 8);
                ctx.pc += 2;
                ctx.stack[ctx.sp++] = val;
                break;
            }
            case OpCode::OP_ADD: {
                if (ctx.sp < 2) return 0;
                uint64_t v2 = ctx.stack[--ctx.sp];
                uint64_t v1 = ctx.stack[--ctx.sp];
                ctx.stack[ctx.sp++] = v1 + v2;
                break;
            }
            case OpCode::OP_SUB: {
                if (ctx.sp < 2) return 0;
                uint64_t v2 = ctx.stack[--ctx.sp];
                uint64_t v1 = ctx.stack[--ctx.sp];
                ctx.stack[ctx.sp++] = v1 - v2;
                break;
            }
            case OpCode::OP_XOR: {
                if (ctx.sp < 2) return 0;
                uint64_t v2 = ctx.stack[--ctx.sp];
                uint64_t v1 = ctx.stack[--ctx.sp];
                ctx.stack[ctx.sp++] = v1 ^ v2;
                break;
            }
            case OpCode::OP_CMP: {
                if (ctx.sp < 2) return 0;
                uint64_t v2 = ctx.stack[--ctx.sp];
                uint64_t v1 = ctx.stack[--ctx.sp];
                ctx.zf = (v1 == v2);
                break;
            }
            case OpCode::OP_JZ: {
                uint8_t offset = bytecode[ctx.pc++];
                if (ctx.zf) ctx.pc += offset;
                break;
            }
            case OpCode::OP_RET:
                return (ctx.sp > 0) ? ctx.stack[--ctx.sp] : 0;
            default:
                return 0;
        }
    }
    return 0;
}

} // namespace IronLock::Modules::VM
