# LM_Disassemble

```python
def LM_Disassemble(code : int : code : int) -> Optional[None]:
```

# Description

Disassembles a single instruction into an `lm_inst_t`.

# Parameters

- code: virtual address of the instruction to be disassembled.

# Return Value

On success, it returns a valid `lm_inst_t` containing the disassembled instruction. On failure, it returns `None`.

