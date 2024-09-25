# X64Emulator

X64Emulator is a simplified emulator for the x86-64 (64-bit) architecture that mimics the behavior of an x64 CPU. It supports a subset of the x86-64 instruction set, emulates general-purpose registers, memory, a stack, and basic flag operations. The emulator is designed to be extensible and provides a framework for implementing additional instructions.

## Features

- Emulates 64-bit general-purpose registers (e.g., `rax`, `rbx`, `rcx`, etc.)
- Simulates 1MB of memory
- Stack manipulation using `push` and `pop`
- Implements basic data movement, arithmetic, and logical instructions:
  - `mov`, `add`, `sub`, `xor`, `cmp`, `test`, and more
- Basic flag operations (`ZF`, `CF`, `SF`, etc.)
- Easily extensible instruction set using C++ lambdas and `std::function`
  
## Usage

The `X64Emulator` class provides a framework for simulating 64-bit operations. You can create an instance of the emulator and execute x64 instructions through its built-in instruction set. Below is an example of how to instantiate and run a few instructions:

```cpp
#include "X64Emulator.h"

int main() {
    X64Emulator emulator;

    // Example usage
    emulator.get_register("rax") = 5;
    emulator.get_register("rbx") = 3;
    
    // Perform some operations
    emulator.add("rax", "rbx");  // rax = rax + rbx
    
    std::cout << "Result in rax: " << emulator.get_register("rax") << std::endl;

    return 0;
}
```

## Supported Instructions

Currently, the following instruction groups are supported:
- **Data Movement**: `mov`, `push`, `pop`, `xchg`, etc.
- **Arithmetic**: `add`, `sub`, `inc`, `dec`, `neg`, etc.
- **Logical**: `and`, `or`, `xor`, `not`, etc.
- **Comparison**: `cmp`, `test`
- **Shift/Rotate**: `shl`, `shr`, `rol`, `ror`, etc.

## Roadmap

- Add support for more x86-64 instructions
- Improve memory management and implement memory-mapped I/O
- Add instruction decoding for binary executable formats (e.g., ELF, PE)
- Implement floating-point instructions and SSE/AVX

## Building

To build X64Emulator, you will need a C++ compiler that supports C++11 or higher. You can optionally use Visual Studio. Here’s how to build the project with `g++`:

```bash
g++ -std=c++11 -o X64Emulator main.cpp
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributions

Feel free to open an issue or submit a pull request if you'd like to contribute or suggest improvements. All contributions are welcome!

---

Thank you for checking out X64Emulator! Let me know if you encounter any issues or have any feedback.