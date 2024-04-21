# LM_IsProcessAlive

```c
LM_API lm_bool_t LM_CALL
LM_IsProcessAlive(const lm_process_t *process);
```

# Description
Checks if a given process is alive based on its PID and start time.

# Parameters
 - `process`: The process that will be checked.

# Return Value
`LM_TRUE` if the process specified by the input `lm_process_t`
is alive or `LM_FALSE` otherwise.
