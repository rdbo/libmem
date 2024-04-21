# LM_FindSymbolAddress

```c
LM_API lm_address_t LM_CALL
LM_FindSymbolAddress(const lm_module_t *module,
		     lm_string_t        symbol_name);
```

# Description
The function `LM_FindSymbolAddress` searches for the address of a symbol within a given module.

# Parameters
 - `module`: The `module` parameter is a pointer to a structure of type `lm_module_t`, which
represents the module where the symbol will be looked up from.
 - `symbol_name`: The `symbol_name` parameter is a string representing the name of the symbol
(function, variable, etc) whose address you want to find within the specified module.

# Return Value
The function `LM_FindSymbolAddress` is returning the address of a symbol with the given name
within the specified module. If the symbol is found, the address of the symbol is returned. If the
symbol is not found or if an error happens, `LM_ADDRESS_BAD` is returned.
