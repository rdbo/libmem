# LM_GetProcessEx

```c
LM_API lm_bool_t LM_CALL
LM_GetProcessEx(lm_pid_t      pid,
		lm_process_t *process_out);
```

# Description
Retrieves information about a specified process identified by its process ID.

# Parameters
 - `pid`: The process ID of the process for which you want to
retrieve information.
 - `process_out`: A pointer to the `lm_process_t` structure that will be
populated with information about the specified process.

# Return Value
`LM_TRUE` if the process information was successfully
retrieved or `LM_FALSE` if there was an issue during the
retrieval process.
