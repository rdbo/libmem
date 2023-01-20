# LM_GetProcessEx

```python
def LM_GetProcessEx(pid : lm_pid_t)
```

# Description

Gets information about a remote process with a known PID.

# Parameters

- pid: ID of the process to get information from.

# Return Value

On success it returns a valid `lm_process_t`. On failure, it returns `None`.

