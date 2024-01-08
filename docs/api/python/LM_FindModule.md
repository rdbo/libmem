# LM_FindModule

```python
def LM_FindModule(name: str) -> Optional[lm_module_t]
```

# Description

Searches for a module in the calling process based on it's name or path.

# Parameters

- name: string containing the name of the module, such as `"gamemodule.dll"` or `"libgamemodule.so"`. It may also be a relative/absolute path, like `"bin/lib/gamemodule.dll"`, or `"/usr/lib/libc.so"`.

# Return Value

On success, it returns a valid `lm_module_t`. On failure, it returns `None`.

