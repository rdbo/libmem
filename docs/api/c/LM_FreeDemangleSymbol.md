# LM_FreeDemangleSymbol

```c
LM_API lm_void_t
LM_FreeDemangleSymbol(lm_cstring_t symbol);
```

# Description

Frees a demangled symbol allocated by `LM_DemangleSymbol`. It must be called if `LM_DemangleSymbol` succeeds with its `symbol` parameter set to `LM_NULLPTR`.

# Parameters

- `symbol`: The allocated demangled symbol name pointer.

# Return Value

This function does not return a value.