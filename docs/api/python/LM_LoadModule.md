# LM_LoadModule

```rust
def LM_LoadModule(modpath : str)
```

# Description

Loads a module into the calling process from its path.

# Parameters

- modpath: string containing a relative/absolute path, like `"bin/lib/gamemodule.dll"`, or `"/usr/lib/libc.so"`.

# Return Value

On success, it returns a valid `lm_module_t` containing information about the loaded module. On failure, it returns `None`.

