# LM_IsProcessAlive

```c
LM_API lm_bool_t
LM_IsProcessAlive(lm_process_t *pproc);
```

# Description

Checks if a process is alive or not

# Parameters

- pproc: pointer to a valid `lm_process_t` variable that will be used to check the process state

# Return Value

It returns `LM_TRUE` is the process is alive, and `LM_FALSE` if the process is dead.

