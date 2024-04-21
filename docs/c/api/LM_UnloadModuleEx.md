# LM_UnloadModuleEx

```c
LM_API lm_bool_t LM_CALL
LM_UnloadModuleEx(const lm_process_t *process,
		  const lm_module_t  *module);
```

# Description
Unloads a module from a specified process.

# Parameters
 - `process`: The process that the module will be unloaded from.
 - `module`: The module that you want to unload from the process.

# Return Value
Returns `LM_TRUE` if the module was successfully unloaded, and `LM_FALSE` if it fails.
