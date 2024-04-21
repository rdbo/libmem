# LM_UnloadModule

```c
LM_API lm_bool_t LM_CALL
LM_UnloadModule(const lm_module_t *module);
```

# Description
Unloads a module from the current process.

# Parameters
 - `module`: The module that you want to unload from the process.

# Return Value
Returns `LM_TRUE` if the module was successfully unloaded, and `LM_FALSE` if it fails.
