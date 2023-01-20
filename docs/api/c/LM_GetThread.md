# LM_GetThread

```c
LM_API lm_bool_t
LM_GetThread(lm_thread_t *thrbuf);
```

# Description

Gets information about the calling thread

# Parameters

- thrbuf: pointer to an `lm_thread_t` variable that will receive the thread information.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

