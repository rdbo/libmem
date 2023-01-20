# LM_GetThreadEx

```c
LM_API lm_bool_t
LM_GetThreadEx(lm_process_t *pproc,
           lm_thread_t  *thrbuf);
```

# Description

Gets information about a thread in a remote process.

# Parameters

- pproc: pointer to a valid process that will be searched for a thread.
- thrbuf: pointer to an `lm_thread_t` variable that will receive the thread information.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

