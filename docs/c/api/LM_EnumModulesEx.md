# LM_EnumModulesEx

```c
LM_API lm_bool_t LM_CALL
LM_EnumModulesEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					       lm_void_t   *arg),
		 lm_void_t          *arg);
```

# Description
The function `LM_EnumModulesEx` enumerates modules in a specified process and calls a callback function
for each module found.

# Parameters
 - `process`: The `process` parameter in the `LM_EnumModulesEx` function is a pointer to a
structure `lm_process_t` which is used to identify the process for which the modules are being
enumerated.
 - `callback`: The `callback` parameter in the `LM_EnumModulesEx` function is a function pointer
that that will receive the current module in the enumeration and an extra argument. This function
should return `LM_TRUE` to continue the enumeration, or `LM_FALSE` to stop it.
 - `arg`: The `arg` parameter in the `LM_EnumModulesEx` function is a pointer to a user-defined
data structure or variable that you can pass to the callback function. This parameter allows you to
provide additional context or data to the callback function when iterating over modules in a
process.

# Return Value
The function returns `LM_TRUE` if the enumeration succeeds or `LM_FALSE` if it fails.
