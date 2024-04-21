# LM_UnloadModule

```c
LM_API lm_bool_t LM_CALL
LM_UnloadModule(const lm_module_t *module);
```

# Description
The function `LM_UnloadModule` unloads a module from the current process.

# Parameters
 - `module`: The `module` parameter represents the module that you want to unload from the process.

# Return Value
The function `LM_UnloadModule` returns `LM_TRUE` if the module was successfully unloaded, and
`LM_FALSE` if there was an error.
