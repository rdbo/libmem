# LM_FreeInstructions

```c
LM_API lm_void_t LM_CALL
LM_FreeInstructions(lm_inst_t *instructions);
```

# Description
The function `LM_FreeInstructions` deallocates the memory allocated by
`LM_DisassembleEx` for the disassembled instructions.

# Parameters
 - `instructions`: The `instructions` parameter is a pointer to the disassembled
instructions returned by `LM_DisassembleEx`

# Return Value
The function does not return a value
