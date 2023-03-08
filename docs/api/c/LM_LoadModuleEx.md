# LM_LoadModuleEx

```c
LM_API lm_bool_t
LM_LoadModuleEx(lm_process_t *pproc,
        lm_string_t   path,
        lm_module_t  *modbuf);
```

# Description

Loads a module into a remote process from its path.

# Parameters

- pproc: pointer to a valid process in which the module will be loaded.
- path: string containing a relative/absolute path, like `"bin/lib/gamemodule.dll"`, or `"/usr/lib/libc.so"`.
- modbuf: optional pointer to an `lm_module_t` variable that will receive the loaded module information.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

