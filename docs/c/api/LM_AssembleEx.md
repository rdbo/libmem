# LM_AssembleEx

```c
LM_API lm_size_t LM_CALL
LM_AssembleEx(lm_string_t  code,
              lm_arch_t    arch,
	      lm_size_t    bits,
	      lm_address_t runtime_address,
	      lm_byte_t  **payload_out);
```

# Description
The function `LM_AssembleEx` assembles one or more instructions into machine code
(must be deallocated with `LM_FreePayload`).

# Parameters
 - `code`: The `code` parameter is a string of the instructions to be assembled.
Example: `"mov eax, ebx ; jmp eax"`.
 - `arch`: The `arch` parameter specifies the architecture to be assembled (`LM_ARCH_` values).
 - `bits`: The `bits` parameter specifies the bits of the architecture to be assembled.
It can be `32` or `64`.
 - `runtime_address`: The `runtime_address` parameter is the runtime address to resolve
the functions (for example, relative jumps will be resolved using this address).
 - `payload_out`: The `payload_out` parameter is a pointer to a variable of type
`lm_byte_t` that will receive the assembled instructions (deallocate after use with
`LM_FreePayload`).

# Return Value
On success, it returns the size of the assembled instructions, in bytes.
On failure, it returns `0`.
