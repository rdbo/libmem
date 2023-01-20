# LM_UnloadModuleEx

```c
LM_API lm_bool_t
LM_UnloadModuleEx(lm_process_t *pproc,
          lm_module_t  *pmod);
```

# Description

Unloads a module from a remote process.

# Parameters

- pproc: valid process which the module will be unloaded from.
- pmod: pointer to an `lm_module_t` variable has the loaded module's information.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

