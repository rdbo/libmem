# LM_UnloadModuleEx

```c
LM_API lm_bool_t LM_CALL
LM_UnloadModuleEx(const lm_process_t *process,
		  const lm_module_t  *module);
```

# Description
The function `LM_UnloadModuleEx` unloads a module from the current process.

# Parameters
 - `process`: The `process` parameter is a pointer to a structure representing a process in the
system. It's the process that the module will be unloaded from.
 - `module`: The `module` parameter represents the module that you want to unload from the process.

# Return Value
The function `LM_UnloadModuleEx` returns `LM_TRUE` if the module was successfully unloaded, and
`LM_FALSE` if there was an error.
