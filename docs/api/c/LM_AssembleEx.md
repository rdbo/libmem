# LM_AssembleEx

```c
LM_API lm_size_t
LM_AssembleEx(lm_cstring_t  code,
          lm_size_t     bits,
          lm_address_t  runtime_addr,
          lm_bytearr_t *pcodebuf);
```

# Description

Assembles one or more instructions into machine code (must be deallocated with `LM_FreeCodeBuffer`).

# Parameters

- code: a string of the instructions to be assembled. Example: `"mov eax, ebx ; jmp eax"`.
- bits: the bits of the architecture to be assembled. It can be `32` or `64`.
- runtime_addr: the runtime address to resolve the functions (for example, relative jumps will be resolved using this address).
- pcodebuf: a pointer to a variable of type `lm_bytearr_t` that will receive the assembled instructions (deallocate after use with `LM_FreeCodeBuffer`).

# Return Value

On success, it returns the size of the assembled instructions, in bytes. On failure, it returns `0`.

