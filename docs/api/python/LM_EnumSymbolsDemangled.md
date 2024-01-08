# LM_EnumSymbolsDemangled

```python
def LM_EnumSymbolsDemangled(pmod : lm_module_t : pmod : lm_module_t) -> Optional[None]:
```

# Description

Enumerates all the demangled symbols in a module, sending them to a callback function.

# Parameters

- pmod: valid module which the demangled symbols will be searched from.

# Return Value

On success, it returns a list containing all valid demangled symbols (`lm_symbol_t`); On failure, it returns `None`.

