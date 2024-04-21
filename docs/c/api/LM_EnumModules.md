# LM_EnumModules

```c
LM_API lm_bool_t LM_CALL
LM_EnumModules(lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					     lm_void_t   *arg),
	       lm_void_t          *arg);
```

# Description
Enumerates modules in the current process and calls a callback function
for each module found.

# Parameters
 - `callback`: The callback function that will receive the current module in
the enumeration and an extra argument. This function should return `LM_TRUE`
to continue the enumeration, or `LM_FALSE` to stop it.
 - `arg`: An extra argument that is passed to the callback function. This allows
you to provide additional information or context to the callback function when
it is invoked during the enumeration of modules.

# Return Value
Returns `LM_TRUE` if the enumeration succeeds, or `LM_FALSE` if it fails.
