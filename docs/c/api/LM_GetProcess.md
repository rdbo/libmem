# LM_GetProcess

```c
LM_API lm_bool_t LM_CALL
LM_GetProcess(lm_process_t *process_out);
```

# Description
Retrieves information about the current process, including its PID,
parent PID, path, name, start time, and architecture bits.

# Parameters
 - `process_out`: A pointer to the `lm_process_t` structure that will be populated
with information about the current process.

# Return Value
`LM_TRUE` if the process information was successfully
retrieved or `LM_FALSE` if there was an error.
