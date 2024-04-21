# LM_FreeDemangledSymbol

```c
LM_API lm_void_t LM_CALL
LM_FreeDemangledSymbol(lm_char_t *symbol_name);
```

# Description
The function `LM_FreeDemangledSymbol` frees the memory allocated for a demangled symbol name allocated
with `LM_DemangleSymbol`.

# Parameters
 - `symbol_name`: The `symbol_name` parameter is a pointer to the string representing the name of a symbol
that has been demangled with `LM_DemangleSymbol` and is also dynamically allocated

# Return Value
The function does not return a value
