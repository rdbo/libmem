# LM_LoadModuleEx

```c
LM_API lm_bool_t LM_CALL
LM_LoadModuleEx(const lm_process_t *process,
		lm_string_t         path,
		lm_module_t        *module_out);
```

# Description
Loads a module from a specified path into a specified process.

# Parameters
 - `process`: The process that the module will be loaded into.
 - `path`: The path of the module to be loaded.
 - `module_out`: A pointer to a `lm_module_t` type, which is used to store information
about the loaded module (optional).

# Return Value
Returns `LM_TRUE` is the module was loaded successfully, or `LM_FALSE` if it fails.
