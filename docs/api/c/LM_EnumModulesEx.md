# LM_EnumModulesEx

```c
LM_API lm_bool_t
LM_EnumModulesEx(lm_process_t *pproc,
		 lm_bool_t   (*callback)(lm_module_t *pmod,
					 lm_void_t   *arg),
		 lm_void_t    *arg);
```

# Description

Enumerates all the modules in a remote process, sending them to a callback function.

# Parameters

- pproc: pointer to a valid process that will be searched for modules.
- callback: pointer to a function that will be called for every module found (received in the parameter `pmod`). It can return either `LM_TRUE` to continue searching for modules or `LM_FALSE` to stop the search.
- arg: An optional extra argument that will be passed into the callback function (use `LM_NULL` to ignore it).

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

