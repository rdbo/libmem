# LM_UnloadModuleEx

```python
def LM_UnloadModuleEx(pproc : lm_process_t, pmod : lm_module_t)
```

# Description

Unloads a module from a remote process.

# Parameters

- pproc: valid process which the module will be unloaded from.
- pmod: valid module that is loaded in the calling process.

# Return Value

On success, it returns a valid `true`. On failure, it returns `false`.

