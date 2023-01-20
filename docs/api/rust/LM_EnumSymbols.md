# LM_EnumSymbols

```rust
pub fn LM_EnumSymbols(pmod : &lm_module_t) -> Option<Vec<lm_symbol_t>>
```

# Description

Enumerates all the symbols in a module, sending them to a callback function.

# Parameters

- pmod: immutable reference to a valid module which the symbols will be searched from.

# Return Value

On success, it returns a `Some(symbol_list)`, where `symbol_list` is a vector containing all valid symbols; On failure, it returns `None`.

