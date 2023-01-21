# LM_Disassemble

```c
LM_API lm_bool_t
LM_Disassemble(lm_address_t code,
           lm_inst_t   *inst);
```

# Description

Disassembles a single instruction into an `lm_inst_t`.

# Parameters

- code: virtual address of the instruction to be disassembled.
- inst: a pointer to a variable of type `lm_inst_t` that will receive the disassembled instruction.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

