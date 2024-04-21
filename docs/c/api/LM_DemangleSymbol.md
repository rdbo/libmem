# LM_DemangleSymbol

```c
LM_API lm_char_t * LM_CALL
LM_DemangleSymbol(lm_string_t symbol_name,
		  lm_char_t  *demangled_buf,
		  lm_size_t   maxsize);
```

# Description
The LM_DemangleSymbol function takes a symbol name, demangles it, and returns the demangled symbol.

# Parameters
 - `symbol_name`: The `symbol_name` parameter is a string representing the name of a symbol that
you want to demangle.
 - `demangled_buf`: The `demangled_buf` parameter is a pointer to a buffer where the demangled
symbol name will be stored. If this is `NULL`, the symbol will be dynamically allocated and `maxsize`
is ignored.
 - `maxsize`: The `maxsize` parameter in the `LM_DemangleSymbol` function represents the maximum
size of the buffer `demangled_buf` where the demangled symbol will be stored.

# Return Value
The function `LM_DemangleSymbol` returns a pointer to the demangled symbol string, or `NULL` if it
fails. If the symbol was dynamically allocated, you need to free it with `LM_FreeDemangledSymbol`.
