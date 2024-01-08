# LM_LoadModuleEx

```python
def LM_LoadModuleEx(pproc : lm_process_t : pproc : lm_process_t, modpath : str : modpath : str) -> Optional[None]:
```

# Description

Loads a module into a remote process from its path.

# Parameters

- pproc: valid process in which the module will be loaded.
- modpath: string containing a relative/absolute path, like `"bin/lib/gamemodule.dll"`, or `"/usr/lib/libc.so"`.

# Return Value

On success, it returns a valid `lm_module_t` containing information about the loaded module. On failure, it returns `None`.

