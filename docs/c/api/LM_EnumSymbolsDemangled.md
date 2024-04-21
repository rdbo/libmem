# LM_EnumSymbolsDemangled

```c
LM_API lm_bool_t LM_CALL
LM_EnumSymbolsDemangled(const lm_module_t  *module,
			lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
						      lm_void_t   *arg),
			lm_void_t          *arg);
```

# Description
Enumerates symbols in a module with demangled names and calls a provided callback function for each
symbol found.

# Parameters
 - `module`: The module where the symbols will be enumerated from.
 - `callback`: A function pointer that will receive each demangled symbol in the enumeration and
an extra argument. The callback function should return `LM_TRUE` to continue the enumeration or
`LM_FALSE` to stop it.
 - `arg`: A pointer to user-defined data that can be passed to the callback function.
It allows you to provide additional information or context.

# Return Value
Returns `LM_TRUE` if the enumeration succeeds, `LM_FALSE` otherwise.
