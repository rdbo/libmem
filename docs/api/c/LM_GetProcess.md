# LM_GetProcess

```c
LM_API lm_bool_t
LM_GetProcess(lm_process_t *procbuf);
```

# Description

Gets information about the calling process

# Parameters

- procbuf: pointer to an `lm_process_t` variable that will receive the process information.

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

