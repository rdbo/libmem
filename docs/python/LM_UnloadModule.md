# LM_UnloadModule

```python
def LM_UnloadModule(pmod: lm_module_t) -> Optional[bool]
```

# Description

Unloads a module from the calling process.

# Parameters

- pmod: valid module that is loaded in the calling process

# Return Value

On success, it returns a valid `true`. On failure, it returns `false`.

