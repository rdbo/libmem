# LM_FindSymbolAddressDemangled

```python
def LM_FindSymbolAddressDemangled(pmod : lm_module_t, name : str)
```

# Description

Searches for a demangled symbol in a module, returning its virtual address.

# Parameters

- pmod: valid module which the demangled symbol will be searched from.
- name: string containing the name of the demangled symbol

# Return Value

On success, it returns is a valid `int` containing the virtual address of the symbol. On failure, it returns `None`.

