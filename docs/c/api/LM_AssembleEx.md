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
The function assembles instructions into machine code.

# Parameters
 - `code`: The instructions to be assembled.
Example: `"mov eax, ebx ; jmp eax"`.
 - `arch`: The architecture to be assembled.
 - `bits`: The bitness of the architecture to be assembled.
It can be `32` or `64`.
 - `runtime_address`: The runtime address to resolve
the addressing (for example, relative jumps will be resolved using this address).
 - `payload_out`: A pointer to the buffer that will receive the assembled instructions.
The buffer should be freed with `LM_FreePayload` after use.

# Return Value
On success, it returns the size of the assembled instructions, in bytes.
On failure, it returns `0`.
