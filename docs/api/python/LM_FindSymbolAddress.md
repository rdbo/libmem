# LM_FindSymbolAddress

```python
def LM_FindSymbolAddress(pmod : lm_module_t, name : str)
```

# Description

Searches for a symbol in a module, returning its virtual address.

# Parameters

- pmod: valid module which the symbol will be searched from.
- name: C string containing the name of the symbol

# Return Value

On success, it returns is a valid `lm_address_t`. On failure, it returns `None`.

