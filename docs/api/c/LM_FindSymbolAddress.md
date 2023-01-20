# LM_FindSymbolAddress

```c
LM_API lm_address_t
LM_FindSymbolAddress(lm_module_t *pmod,
             lm_cstring_t name);
```

# Description

Searches for a symbol in a module, returning its virtual address.

# Parameters

- pmod: pointer to a valid module which the symbol will be searched from.
- name: C string containing the name of the symbol

# Return Value

On success, it returns the symbol address. On failure, it returns `LM_ADDRESS_BAD`.

