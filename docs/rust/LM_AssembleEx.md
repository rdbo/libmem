# LM_AssembleEx

```rust
pub fn LM_AssembleEx(code : &str, bits : lm_size_t, runtime_addr : lm_address_t) -> Option<Vec<u8>>
```

# Description

Assembles one or more instructions into machine code.

# Parameters

- code: a string of the instructions to be assembled. Example: `"mov eax, ebx ; jmp eax"`.
- bits: the bits of the architecture to be assembled. It can be `32` or `64`.
- runtime_addr: the runtime address to resolve the functions (for example, relative jumps will be resolved using this address).

# Return Value

On success, it returns `Some(instructions)`, where `instructions` is a vector of bytes containing the assembled instructions. On failure, it returns `None`.

