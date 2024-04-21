# LM_FreePayload

```c
LM_API lm_void_t LM_CALL
LM_FreePayload(lm_byte_t *payload);
```

# Description
The function `LM_FreePayload` frees memory allocated by `LM_AssembleEx`.

# Parameters
 - `payload`: The `payload` parameter is a pointer to a buffer that was allocated by
`LM_AssembleEx` and needs to be freed

# Return Value
The function does not return a value
