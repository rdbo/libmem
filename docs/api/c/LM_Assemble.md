# LM_Assemble

```c
LM_API lm_bool_t
LM_Assemble(lm_cstring_t code,
        lm_inst_t   *inst);
```

# Description

Assembles a single instruction into machine code.

# Parameters

- code: a string of the instruction to be assembled. Example: `"jmp eax"`.
- inst: a pointer to a variable of type `lm_inst_t` that will receive the assembled instruction.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

