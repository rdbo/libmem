# LM_UnloadModule

```c
LM_API lm_bool_t
LM_UnloadModule(lm_module_t *pmod);
```

# Description

Unloads a module from the calling process.

# Parameters

- pmod: pointer to an `lm_module_t` variable has the loaded module's information.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

