# LM_EnumSymbols

```python
def LM_EnumSymbols(pmod : lm_module_t : pmod : lm_module_t) -> Optional[None]:
```

# Description

Enumerates all the symbols in a module, sending them to a callback function.

# Parameters

- pmod: valid module which the symbols will be searched from.

# Return Value

On success, it returns a list containing all valid symbols (`lm_symbol_t`); On failure, it returns `None`.

