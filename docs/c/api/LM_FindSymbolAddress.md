# LM_FindSymbolAddress

```c
LM_API lm_address_t LM_CALL
LM_FindSymbolAddress(const lm_module_t *module,
		     lm_string_t        symbol_name);
```

# Description
Finds the address of a symbol within a module.

# Parameters
 - `module`: The module where the symbol will be looked up from.
 - `symbol_name`: The name of the symbol to look up.

# Return Value
Returns the address of the symbol, or `LM_ADDRESS_BAD` if it fails.
