# LM_DemangleSymbol

```python
def LM_DemangleSymbol(symbol: str) -> Optional[str]
```

# Description

Demangles a symbol name, generally acquired from `LM_EnumSymbols`.

NOTE: You might want to use `LM_EnumSymbolsDemangled` or `LM_FindSymbolAddressDemangled`.

# Parameters

- `symbol`: string containing the mangled symbol name

# Return Value

On success, it returns is a valid `str` containing the demangled symbol name. On failure, it returns `None`.

