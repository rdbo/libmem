# LM_DemangleSymbol

```rust
pub fn LM_DemangleSymbol(symbol: &str) -> Option<String>
```

# Description


Demangles a symbol name, generally acquired from `LM_EnumSymbols`.

NOTE: You might want to use `LM_EnumSymbolsDemangled` or `LM_FindSymbolAddressDemangled`.

# Parameters

- `symbol`: The mangled symbol name string.

# Return Value

On success, it returns `Some(symbol)`, where `symbol` is a valid `String` containing the demangled symbol. On failure, it returns `None`.

