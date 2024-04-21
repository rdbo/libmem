# LM_DisassembleEx

```c
LM_API lm_size_t LM_CALL
LM_DisassembleEx(lm_address_t machine_code,
		 lm_arch_t    arch,
		 lm_size_t    bits,
		 lm_size_t    max_size,
		 lm_size_t    instruction_count,
		 lm_address_t runtime_address,
		 lm_inst_t  **instructions_out);
```

# Description
The function disassembles instructions into an array of
`lm_inst_t` structs.

# Parameters
 - `machine_code`: The address of the instructions to be disassembled.
 - `arch`: The architecture to be disassembled.
 - `bits`: The bitness of the architecture to be disassembled.
It can be `32` or `64`.
 - `max_size`: The maximum number of bytes to disassemble (0 for as
many as possible, limited by `instruction_count`).
 - `instruction_count`: The amount of instructions
to disassemble (0 for as many as possible, limited by `max_size`).
 - `runtime_address`: The runtime address to resolve
the addressing (for example, relative jumps will be resolved using this address).
 - `instructions_out`: A pointer to the buffer that will receive the disassembled instructions.
The buffer should be freed with `LM_FreeInstructions` after use.

# Return Value
On success, it returns the count of the instructions disassembled. On failure, it
returns `0`.
