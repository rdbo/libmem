# LM_DisassembleEx

```rust
pub fn LM_DisassembleEx(code : lm_address_t, bits : lm_size_t, size : lm_size_t, count : lm_size_t, runtime_addr : lm_address_t) -> Option<Vec<lm_inst_t>>
```

# Description

Disassembles one or more instructions into `lm_inst_t`'s.

# Parameters

- code: virtual address of the instructions to be disassembled.
- bits: the bits of the architecture to be disassembled. It can be `32` or `64`.
- size: the maximum size in bytes for the disassembly.
- count: the amount of instructions to be disassembled (0 for as many as possible)
- runtime_addr: the runtime address to resolve the functions (for example, relative jumps will be resolved using this address).

# Return Value

On success, it returns `Some(instructions)`, where `instructions` is a vector of `lm_inst_t`'s containing the disassembled instructions. On failure, it returns `None`.

