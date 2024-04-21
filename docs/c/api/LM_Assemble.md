# LM_Assemble

```c
LM_API lm_bool_t LM_CALL
LM_Assemble(lm_string_t code,
	     lm_inst_t  *instruction_out);
```

# Description
The function `LM_Assemble` assembles a single instruction into machine code

# Parameters
 - `code`: The `code` parameter is a string of the instruction to be assembled.
Example: `"mov eax, ebx"`.
 - `instruction_out`: The `instruction_out` parameter is a pointer to a `lm_inst_t` which
will be populated with the assembled instruction.

# Return Value
The function `LM_Assemble` returns `LM_TRUE` if it succeeds in assembling the instruction, and
populates the `instruction_out` parameter with a `lm_inst_t` that contains the assembled instruction.
If the instruction could not be assembled successfully, then the function returns `LM_FALSE`.
