# LM_FindSymbolAddress

```rust
pub fn LM_FindSymbolAddress(pmod : &lm_module_t, name : &str) -> Option<lm_address_t>
```

# Description

Searches for a symbol in a module, returning its virtual address.

# Parameters

- pmod: immutable reference to a valid module which the symbol will be searched from.
- name: C string containing the name of the symbol

# Return Value

On success, it returns `Some(address)`, where `process` is a valid `lm_address_t`. On failure, it returns `None`.

