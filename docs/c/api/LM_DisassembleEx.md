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
The function `LM_DisassembleEx` disassembles one or more instructions into an array of
`lm_inst_t` structs.

# Parameters
 - `machine_code`: The `machine_code` parameter is the address of the instructions to be
disassembled.
 - `arch`: The `arch` parameter is the architecture to be disassembled (see `lm_arch_t`
for available architectures).
 - `bits`: The `bits` parameter is the bitness of the architecture to be disassembled (32 or 64).
 - `max_size`: The `max_size` parameter is the maximum number of bytes to disassemble (0 for as
many as possible, limited by `instruction_count`).
 - `instruction_count`: The `instruction_count` parameter is the amount of instructions
to disassemble (0 for as many as possible, limited by `max_size`).
 - `runtime_address`: The `runtime_address` parameter is the runtime address to resolve
the functions (for example, relative jumps will be resolved using this address).
 - `instructions_out`: The `instructions_out` parameter is a pointer to a variable of type
`lm_inst_t` that will receive the disassembled instructions (deallocate after use with
`LM_FreeInstructions`).

# Return Value
On success, it returns the count of the instructions disassembled. On failure, it
returns `0`.
