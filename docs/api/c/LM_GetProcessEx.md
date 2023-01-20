# LM_GetProcessEx

```c
LM_API lm_bool_t
LM_GetProcessEx(lm_pid_t      pid,
		lm_process_t *procbuf);
```

# Description

Gets information about a remote process with a known PID

# Parameters

- pid: ID of the process to get information from.
- procbuf: pointer to an `lm_process_t` variable that will receive the process information.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

