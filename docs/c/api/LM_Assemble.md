# LM_Assemble

```c
LM_API lm_bool_t LM_CALL
LM_Assemble(lm_string_t code,
	     lm_inst_t  *instruction_out);
```

# Description
The function assembles a single instruction into machine code.

# Parameters
 - `code`: The instruction to be assembled.
Example: `"mov eax, ebx"`.
 - `instruction_out`: The assembled instruction is populated into this parameter.

# Return Value
The function returns `LM_TRUE` if it succeeds in assembling the instruction, and
populates the `instruction_out` parameter with the assembled instruction.
If the instruction could not be assembled successfully, then the function returns `LM_FALSE`.
