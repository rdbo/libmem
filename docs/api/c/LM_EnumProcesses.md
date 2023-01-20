# LM_EnumProcesses

```c
LM_API lm_bool_t
LM_EnumProcesses(lm_bool_t (*callback)(lm_process_t *pproc,
				       lm_void_t    *arg),
		 lm_void_t *arg);
```

# Description

Enumerates all the current existing processes, sending them to a callback function.

# Parameters

- callback: pointer to a function that will be called for every process found (received in the parameter `pproc`). It can return either `LM_TRUE` to continue searching for processes or `LM_FALSE` to stop the search.
- arg: An optional extra argument that will be passed into the callback function (use `LM_NULL` to ignore it).

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

