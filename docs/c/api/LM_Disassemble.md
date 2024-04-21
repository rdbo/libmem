# LM_Disassemble

```c
LM_API lm_bool_t LM_CALL
LM_Disassemble(lm_address_t machine_code,
		lm_inst_t   *instruction_out);
```

# Description
The function disassembles one instruction into an `lm_inst_t` struct.

# Parameters
 - `machine_code`: The address of the instruction to be disassembled.
 - `instruction_out`: The disassembled instruction is populated into this parameter.

# Return Value
`LM_TRUE` on success, `LM_FALSE` on failure.
