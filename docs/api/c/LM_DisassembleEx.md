# LM_DisassembleEx

```c
LM_API lm_size_t
LM_DisassembleEx(lm_address_t code,
         lm_size_t    bits,
         lm_size_t    size,
         lm_size_t    count,
         lm_address_t runtime_addr,
         lm_inst_t  **pinsts);
```

# Description

Disassembles one or more instructions into `lm_inst_t`'s (must be deallocated with `LM_FreeInstructions`).

# Parameters

- code: virtual address of the instructions to be disassembled.
- bits: the bits of the architecture to be disassembled. It can be `32` or `64`.
- size: the maximum size in bytes for the disassembly.
- count: the amount of instructions to be disassembled (0 for as many as possible)
- runtime_addr: the runtime address to resolve the functions (for example, relative jumps will be resolved using this address).
- pinsts: a pointer to a variable of type `lm_inst_t *` that will receive the disassembled instructions (deallocate after use with `LM_FreeInstructions`).

# Return Value

On success, it returns the count of the instructions disassembled. On failure, it returns `0`.

