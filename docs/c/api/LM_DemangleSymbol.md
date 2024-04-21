# LM_DemangleSymbol

```c
LM_API lm_char_t * LM_CALL
LM_DemangleSymbol(lm_string_t symbol_name,
		  lm_char_t  *demangled_buf,
		  lm_size_t   maxsize);
```

# Description
Demangles a symbol name.

# Parameters
 - `symbol_name`: The symbol name to demangle.
 - `demangled_buf`: The buffer where the demangled symbol name will be stored.
If this is `NULL`, the symbol will be dynamically allocated and `maxsize` is ignored.
 - `maxsize`: The maximum size of the buffer where the demangled symbol name will be stored.

# Return Value
Returns a pointer to the demangled symbol string, or `NULL` if it fails.
If the symbol was dynamically allocated, you need to free it with `LM_FreeDemangledSymbol`.
