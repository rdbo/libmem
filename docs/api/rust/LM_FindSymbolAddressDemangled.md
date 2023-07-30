# LM_FindSymbolAddressDemangled

```rust
pub fn LM_FindSymbolAddressDemangled(pmod : &lm_module_t, name : &str) -> Option<lm_address_t>
```

# Description

Searches for a demangled symbol in a module, returning its virtual address.

# Parameters

- pmod: immutable reference to a valid module which the symbol will be searched from.
- name: String containing the name of the demangled symbol

# Return Value

On success, it returns `Some(address)`, where `process` is a valid `lm_address_t` containing the virtual address of the demangled symbol. On failure, it returns `None`.

