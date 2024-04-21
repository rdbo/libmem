# LM_GetThread

```c
LM_API lm_bool_t LM_CALL
LM_GetThread(lm_thread_t *thread_out);
```

# Description
Retrieves information about the thread it's running from.

# Parameters
 - `thread_out`: A pointer to the `lm_thread_t` structure that will be populated
with information about the current thread, specifically the thread ID (`tid`) and
the process ID (`owner_pid`).

# Return Value
`LM_TRUE` if the thread information was successfully
retrieved and stored in the provided `lm_thread_t` structure.
Otherwise, the function returns `LM_FALSE`.
