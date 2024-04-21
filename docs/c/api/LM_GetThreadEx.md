# LM_GetThreadEx

```c
LM_API lm_bool_t LM_CALL
LM_GetThreadEx(const lm_process_t *process,
	       lm_thread_t        *thread_out);
```

# Description
Retrieves information about a thread in a process.

# Parameters
 - `process`: The process that the thread will be retrieved from.
 - `thread_out`: A pointer to the `lm_thread_t` variable where the function will
store the thread information retrieved from the process.

# Return Value
`LM_TRUE` if the thread was retrieved successfully, or
`LM_FALSE` if it fails.
