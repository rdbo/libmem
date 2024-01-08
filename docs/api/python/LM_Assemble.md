# LM_Assemble

```python
def LM_Assemble(code: str) -> Optional[lm_inst_t]
```

# Description

Assembles a single instruction into machine code.

# Parameters

- code: a string of the instruction to be assembled. Example: `"jmp eax"`.

# Return Value

On success, it returns a valid `lm_inst_t` containing the assembled instruction. On failure, it returns `None`.

