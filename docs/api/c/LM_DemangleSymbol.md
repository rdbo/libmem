# LM_DemangleSymbol

```c
LM_API lm_cstring_t
LM_DemangleSymbol(lm_cstring_t symbol,
		  lm_cchar_t  *demangled,
		  lm_size_t    maxsize);
```

# Description

Demangles a symbol name, generally acquired from `LM_EnumSymbols`.
NOTE: You might want to use `LM_EnumSymbolsDemangled` or `LM_FindSymbolAddressDemangled`.

# Parameters

- `symbol`: The mangled symbol name C string.
- `demangled`: (optional) The output buffer of size `maxsize` where the demangled symbol name will be stored. If its value is `LM_NULLPTR`, a new value will be allocated and must be freed with `LM_FreeDemangleSymbol`.
- `maxsize`: (optional) The size of the `demangled` buffer, including the `NULL` terminator. It can be 0 if `demangled` is `LM_NULLPTR`.

# Return Value

On success, it returns a pointer to the demangled symbol string. On failure, it returns `LM_NULLPTR`.

