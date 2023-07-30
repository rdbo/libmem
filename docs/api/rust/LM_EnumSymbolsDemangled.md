# LM_EnumSymbolsDemangled

```rust
pub fn LM_EnumSymbolsDemangled(pmod : &lm_module_t) -> Option<Vec<lm_symbol_t>>
```

# Description

Enumerates all the demangled symbols in a module, sending them to a callback function.

# Parameters

- pmod: immutable reference to a valid module which the demangled symbols will be searched from.

# Return Value

On success, it returns a `Some(symbol_list)`, where `symbol_list` is a vector containing all valid demangled symbols. On failure, it returns `None`.

