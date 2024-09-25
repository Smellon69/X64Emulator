#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <cstdint>
#include <iomanip>
#include <bitset>
#include <stdexcept>

class X64Emulator {
private:
    // 64-bit general purpose registers
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;
    // Instruction pointer
    uint64_t rip;
    // Flags register
    uint64_t rflags;
    // Extended general-purpose registers
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

    // Memory (simplified as a vector of bytes)
    std::vector<uint8_t> memory;

    // Stack (simplified)
    std::vector<uint64_t> stack;

    // Instruction set
    std::unordered_map<std::string, std::function<void(const std::string&, const std::string&)>> instructions;

    // Flag bits
    enum Flag {
        CF = 0,  // Carry Flag
        PF = 2,  // Parity Flag
        AF = 4,  // Auxiliary Carry Flag
        ZF = 6,  // Zero Flag
        SF = 7,  // Sign Flag
        OF = 11  // Overflow Flag
    };

public:
    X64Emulator() : rax(0), rbx(0), rcx(0), rdx(0), rsi(0), rdi(0), rsp(0), rbp(0),
        rip(0), rflags(0), r8(0), r9(0), r10(0), r11(0), r12(0), r13(0), r14(0), r15(0) {
        memory.resize(1024 * 1024, 0); // 1MB of memory
        init_instructions();
    }

    void init_instructions() {
        // Data Movement Instructions
        instructions["mov"] = [this](const std::string& dest, const std::string& src) { mov(dest, src); };
        instructions["movzx"] = [this](const std::string& dest, const std::string& src) { movzx(dest, src); };
        instructions["movsx"] = [this](const std::string& dest, const std::string& src) { movsx(dest, src); };
        instructions["lea"] = [this](const std::string& dest, const std::string& src) { lea(dest, src); };
        instructions["push"] = [this](const std::string& src, const std::string&) { push(src); };
        instructions["pop"] = [this](const std::string& dest, const std::string&) { pop(dest); };
        instructions["xchg"] = [this](const std::string& op1, const std::string& op2) { xchg(op1, op2); };

        // Arithmetic Instructions
        instructions["add"] = [this](const std::string& dest, const std::string& src) { add(dest, src); };
        instructions["sub"] = [this](const std::string& dest, const std::string& src) { sub(dest, src); };
        instructions["mul"] = [this](const std::string& src, const std::string&) { mul(src); };
        instructions["imul"] = [this](const std::string& src, const std::string&) { imul(src); };
        instructions["div"] = [this](const std::string& src, const std::string&) { div(src); };
        instructions["idiv"] = [this](const std::string& src, const std::string&) { idiv(src); };
        instructions["inc"] = [this](const std::string& dest, const std::string&) { inc(dest); };
        instructions["dec"] = [this](const std::string& dest, const std::string&) { dec(dest); };
        instructions["neg"] = [this](const std::string& dest, const std::string&) { neg(dest); };
        instructions["adc"] = [this](const std::string& dest, const std::string& src) { adc(dest, src); };
        instructions["sbb"] = [this](const std::string& dest, const std::string& src) { sbb(dest, src); };
        instructions["cmp"] = [this](const std::string& op1, const std::string& op2) { cmp(op1, op2); };
        instructions["test"] = [this](const std::string& op1, const std::string& op2) { test(op1, op2); };

        // Logical Instructions
        instructions["and"] = [this](const std::string& dest, const std::string& src) { and_op(dest, src); };
        instructions["or"] = [this](const std::string& dest, const std::string& src) { or_op(dest, src); };
        instructions["xor"] = [this](const std::string& dest, const std::string& src) { xor_op(dest, src); };
        instructions["not"] = [this](const std::string& dest, const std::string&) { not_op(dest); };
        instructions["shl"] = [this](const std::string& dest, const std::string& count) { shl(dest, count); };
        instructions["shr"] = [this](const std::string& dest, const std::string& count) { shr(dest, count); };
        instructions["sar"] = [this](const std::string& dest, const std::string& count) { sar(dest, count); };
        instructions["rol"] = [this](const std::string& dest, const std::string& count) { rol(dest, count); };
        instructions["ror"] = [this](const std::string& dest, const std::string& count) { ror(dest, count); };
        instructions["bt"] = [this](const std::string& op1, const std::string& op2) { bt(op1, op2); };
        instructions["bsf"] = [this](const std::string& dest, const std::string& src) { bsf(dest, src); };
        instructions["bsr"] = [this](const std::string& dest, const std::string& src) { bsr(dest, src); };

        // Flag Control Instructions
        instructions["stc"] = [this](const std::string&, const std::string&) { stc(); };
        instructions["clc"] = [this](const std::string&, const std::string&) { clc(); };
        instructions["cmc"] = [this](const std::string&, const std::string&) { cmc(); };
        //instructions["cld"] = [this](const std::string&, const std::string&) { cld(); };
        //instructions["std"] = [this](const std::string&, const std::string&) { std(); };
        instructions["lahf"] = [this](const std::string&, const std::string&) { lahf(); };
        instructions["sahf"] = [this](const std::string&, const std::string&) { sahf(); };
    }

    uint64_t& get_register(const std::string& reg) {
        if (reg == "rax") return rax;
        if (reg == "rbx") return rbx;
        if (reg == "rcx") return rcx;
        if (reg == "rdx") return rdx;
        if (reg == "rsi") return rsi;
        if (reg == "rdi") return rdi;
        if (reg == "rsp") return rsp;
        if (reg == "rbp") return rbp;
        if (reg == "rip") return rip;
        if (reg == "r8") return r8;
        if (reg == "r9") return r9;
        if (reg == "r10") return r10;
        if (reg == "r11") return r11;
        if (reg == "r12") return r12;
        if (reg == "r13") return r13;
        if (reg == "r14") return r14;
        if (reg == "r15") return r15;
        throw std::runtime_error("Invalid register: " + reg);
    }

    // Implement all the instruction methods here
    void mov(const std::string& dest, const std::string& src) { get_register(dest) = get_register(src); }
    void movzx(const std::string& dest, const std::string& src) { /* Not implemented */ }
    void movsx(const std::string& dest, const std::string& src) { /* Not implemented */ }
    void lea(const std::string& dest, const std::string& src) { /* Not implemented */ }
    void push(const std::string& src) { stack.push_back(get_register(src)); }
    void pop(const std::string& dest) { get_register(dest) = stack.back(); stack.pop_back(); }
    void xchg(const std::string& op1, const std::string& op2) {
        uint64_t temp = get_register(op1);
        get_register(op1) = get_register(op2);
        get_register(op2) = temp;
    }

    void add(const std::string& dest, const std::string& src) {
        uint64_t result = get_register(dest) + get_register(src);
        set_flag(CF, result < get_register(dest));
        set_flag(ZF, result == 0);
        set_flag(SF, (result & (1ULL << 63)) != 0);
        // OF and AF flags are more complex and omitted for brevity
        get_register(dest) = result;
    }

    void sub(const std::string& dest, const std::string& src) {
        uint64_t result = get_register(dest) - get_register(src);
        set_flag(CF, get_register(dest) < get_register(src));
        set_flag(ZF, result == 0);
        set_flag(SF, (result & (1ULL << 63)) != 0);
        // OF and AF flags are more complex and omitted for brevity
        get_register(dest) = result;
    }

    void mul(const std::string& src) { /* Not implemented */ }
    void imul(const std::string& src) { /* Not implemented */ }
    void div(const std::string& src) { /* Not implemented */ }
    void idiv(const std::string& src) { /* Not implemented */ }
    void inc(const std::string& dest) { ++get_register(dest); }
    void dec(const std::string& dest) { --get_register(dest); }
    void neg(const std::string& dest) { get_register(dest) = -static_cast<int64_t>(get_register(dest)); }
    void adc(const std::string& dest, const std::string& src) { /* Not implemented */ }
    void sbb(const std::string& dest, const std::string& src) { /* Not implemented */ }

    void cmp(const std::string& op1, const std::string& op2) {
        uint64_t val1 = get_register(op1);
        uint64_t val2 = get_register(op2);
        uint64_t result = val1 - val2;
        set_flag(CF, val1 < val2);
        set_flag(ZF, result == 0);
        set_flag(SF, (result & (1ULL << 63)) != 0);
        // OF is set if the operands were of the same sign and the result is of the opposite sign
        set_flag(OF, ((val1 ^ val2) & (val1 ^ result)) & (1ULL << 63));
    }

    void test(const std::string& op1, const std::string& op2) {
        uint64_t val1 = get_register(op1);
        uint64_t val2 = get_register(op2);
        uint64_t result = val1 & val2;
        set_flag(ZF, result == 0);
        set_flag(SF, (result & (1ULL << 63)) != 0);
        set_flag(PF, std::bitset<8>(result).count() % 2 == 0); // Set parity flag
        // CF and OF are always cleared for test
        set_flag(CF, false);
        set_flag(OF, false);
    }

    void and_op(const std::string& dest, const std::string& src) {
        get_register(dest) &= get_register(src);
        set_flag(CF, false);
        set_flag(OF, false);
        set_flag(ZF, get_register(dest) == 0);
        set_flag(SF, (get_register(dest) & (1ULL << 63)) != 0);
        // PF is more complex and omitted for brevity
    }

    void or_op(const std::string& dest, const std::string& src) {
        get_register(dest) |= get_register(src);
        set_flag(CF, false);
        set_flag(OF, false);
        set_flag(ZF, get_register(dest) == 0);
        set_flag(SF, (get_register(dest) & (1ULL << 63)) != 0);
        // PF is more complex and omitted for brevity
    }

    void xor_op(const std::string& dest, const std::string& src) {
        get_register(dest) ^= get_register(src);
        set_flag(CF, false);
        set_flag(OF, false);
        set_flag(ZF, get_register(dest) == 0);
        set_flag(SF, (get_register(dest) & (1ULL << 63)) != 0);
        set_flag(PF, std::bitset<8>(get_register(dest)).count() % 2 == 0); // Set parity flag
    }

    void not_op(const std::string& dest) { get_register(dest) = ~get_register(dest); }
    
    void shl(const std::string& dest, const std::string& count) { /* Not implemented */ }

    void shr(const std::string& dest, const std::string& count) { /* Not implemented */ }

    void sar(const std::string& dest, const std::string& count) {
        uint64_t cnt = get_register(count) & 0x3F; // Limit shift to 0-63
        int64_t signed_val = static_cast<int64_t>(get_register(dest));
        int64_t result = signed_val >> cnt;
        set_flag(CF, (signed_val >> (cnt - 1)) & 1); // Set carry flag
        set_flag(ZF, result == 0);
        set_flag(SF, (result & (1ULL << 63)) != 0);
        get_register(dest) = result;
    }

    void rol(const std::string& dest, const std::string& count) { /* Not implemented */ }
    void ror(const std::string& dest, const std::string& count) { /* Not implemented */ }
    void bt(const std::string& op1, const std::string& op2) { /* Not implemented */ }
    void bsf(const std::string& dest, const std::string& src) { /* Not implemented */ }
    void bsr(const std::string& dest, const std::string& src) { /* Not implemented */ }

    void stc() { set_flag(CF, true); }
    void clc() { set_flag(CF, false); }
    void cmc() { set_flag(CF, !get_flag(CF)); }
    //void cld() { set_flag(DF, false); }
    //void std() { set_flag(DF, true); }
    void lahf() { /* Not implemented */ }
    void sahf() { /* Not implemented */ }

    void set_flag(Flag flag, bool value) {
        if (value) {
            rflags |= (1ULL << flag);
        }
        else {
            rflags &= ~(1ULL << flag);
        }
    }

    bool get_flag(Flag flag) {
        return (rflags & (1ULL << flag)) != 0;
    }

    void execute(const std::string& instruction, const std::string& op1, const std::string& op2 = "") {
        if (instructions.find(instruction) != instructions.end()) {
            instructions[instruction](op1, op2);
            rip++; // Increment instruction pointer after each instruction
        }
        else {
            throw std::runtime_error("Unsupported instruction: " + instruction);
        }
    }

    void set_register(const std::string& reg, uint64_t value) {
        get_register(reg) = value;
    }

    uint64_t get_register_value(const std::string& reg) {
        return get_register(reg);
    }

    void print_registers() {
        std::cout << std::hex << std::setfill('0');
        std::cout << "RAX: 0x" << std::setw(16) << rax << "\tR8:  0x" << std::setw(16) << r8 << std::endl;
        std::cout << "RBX: 0x" << std::setw(16) << rbx << "\tR9:  0x" << std::setw(16) << r9 << std::endl;
        std::cout << "RCX: 0x" << std::setw(16) << rcx << "\tR10: 0x" << std::setw(16) << r10 << std::endl;
        std::cout << "RDX: 0x" << std::setw(16) << rdx << "\tR11: 0x" << std::setw(16) << r11 << std::endl;
        std::cout << "RSI: 0x" << std::setw(16) << rsi << "\tR12: 0x" << std::setw(16) << r12 << std::endl;
        std::cout << "RDI: 0x" << std::setw(16) << rdi << "\tR13: 0x" << std::setw(16) << r13 << std::endl;
        std::cout << "RSP: 0x" << std::setw(16) << rsp << "\tR14: 0x" << std::setw(16) << r14 << std::endl;
        std::cout << "RBP: 0x" << std::setw(16) << rbp << "\tR15: 0x" << std::setw(16) << r15 << std::endl;
        std::cout << "RIP: 0x" << std::setw(16) << rip << std::endl;
        std::cout << "RFLAGS: 0x" << std::setw(16) << rflags << std::endl;
    }
};

int main() {
    X64Emulator emulator;

    // Set initial values
    emulator.set_register("rax", 0x1000);
    emulator.set_register("rbx", 0x2000);
    emulator.set_register("rcx", 0x3000);
    emulator.set_register("rdx", 0x4000);
    emulator.set_register("r8", 0x5000);
    emulator.set_register("r9", 0x6000);
    emulator.set_register("r10", 0x7000);
    emulator.set_register("r11", 0x8000);
    emulator.set_register("r12", 0x9000);
    emulator.set_register("r13", 0xA000);
    emulator.set_register("r14", 0xB000);
    emulator.set_register("r15", 0xC000);

    std::cout << "Initial state:" << std::endl;
    emulator.print_registers();
    std::cout << std::endl;

    // Demonstrate various instructions

    // Data movement
    emulator.execute("mov", "rsi", "rax");      // MOV
    emulator.execute("movzx", "rdx", "ax");     // MOVZX
    emulator.execute("movsx", "rcx", "bx");     // MOVSX
    emulator.execute("lea", "rdi", "[rbx+8]");  // LEA

    // Arithmetic
    emulator.execute("add", "rax", "rbx");      // ADD
    emulator.execute("sub", "rcx", "rdx");      // SUB
    emulator.execute("inc", "rdx");             // INC
    emulator.execute("dec", "r8");              // DEC
    emulator.execute("neg", "r9");              // NEG

    // Logical
    emulator.execute("xor", "r8", "r9");        // XOR
    emulator.execute("and", "r10", "r11");      // AND
    emulator.execute("or", "r12", "r13");       // OR
    emulator.execute("not", "rcx");             // NOT

    // Bitwise shifts
    emulator.execute("shl", "r14", "1");        // SHL
    emulator.execute("shr", "rax", "1");        // SHR

    // Stack operations
    emulator.execute("push", "rax");            // PUSH
    emulator.execute("pop", "rbx");             // POP

    // XCHG - Exchange two operands
    emulator.execute("xchg", "r14", "r15");

    // Conditional move based on flags (CMOVcc)
    emulator.execute("cmp", "rax", "rbx");      // Set condition flags for comparison

    std::cout << "Final state:" << std::endl;
    emulator.print_registers();
    std::cout << std::endl;

    return 0;
}