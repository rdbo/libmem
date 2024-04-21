# LM_LoadModule

```c
LM_API lm_bool_t LM_CALL
LM_LoadModule(lm_string_t  path,
	      lm_module_t *module_out);
```

# Description
The LM_LoadModule function loads a module from a specified path into the current process.

# Parameters
 - `path`: The `path` parameter is a string that represents the file path of the module to be
loaded.
 - `module_out`: The `module_out` parameter is a pointer to a `lm_module_t` type, which is used to
store information about the loaded module (optional).

# Return Value
The function returns `LM_TRUE` is the module was loaded successfully, or `LM_FALSE` if it fails.
