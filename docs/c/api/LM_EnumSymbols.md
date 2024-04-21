# LM_EnumSymbols

```c
LM_API lm_bool_t LM_CALL
LM_EnumSymbols(const lm_module_t  *module,
	       lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
					     lm_void_t   *arg),
	       lm_void_t          *arg);
```

# Description
The function `LM_EnumSymbols` enumerates symbols in a module and calls a callback function for each
symbol found.

# Parameters
 - `module`: The `module` parameter is a pointer to a structure of type `lm_module_t`, which
represents the module where the symbols will be enumerated from.
 - `callback`: The `callback` parameter in the `LM_EnumSymbols` function is a function pointer
that that will receive the current symbol in the enumeration and an extra argument. This function
should return `LM_TRUE` to continue the enumeration, or `LM_FALSE` to stop it.
 - `arg`: The `arg` parameter in the `LM_EnumSymbols` function is a pointer to a user-defined data
structure or variable that will be passed to the callback function `callback` for each symbol that
is enumerated. This allows the user to provide additional context or data that may be needed during
the symbol

# Return Value
The function `LM_EnumSymbols` returns `LM_TRUE` if the enumeration succeeds. Otherwise,
it returns `LM_FALSE`.
