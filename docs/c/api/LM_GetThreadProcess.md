# LM_GetThreadProcess

```c
LM_API lm_bool_t LM_CALL
LM_GetThreadProcess(const lm_thread_t *thread,
		    lm_process_t      *process_out);
```

# Description
Retrieves the process that owns a given thread.

# Parameters
 - `thread`: The thread whose process will be retrieved.
 - `process_out`: A pointer to the `lm_process_t` structure where the function
`LM_GetThreadProcess` will store the process information related to
the given thread.

# Return Value
`LM_TRUE` if the operation was successful or `LM_FALSE`
otherwise.
