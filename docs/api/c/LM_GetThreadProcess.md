# LM_GetThreadProcess

```c
LM_API lm_bool_t
LM_GetThreadProcess(lm_thread_t  *pthr,
            lm_process_t *procbuf);
```

# Description

Gets an `lm_process_t` from an `lm_thread_t`. It is especially useful when you want to interact with a specific thread of a process.

# Parameters

- pthr: pointer to a valid `lm_thread_t` that will be used to find a process.
- procbuf: pointer to an `lm_process_t` variable that will receive the process information.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

