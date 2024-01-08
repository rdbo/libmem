# LM_GetThreadProcess

```python
def LM_GetThreadProcess(pthr: lm_thread_t) -> Optional[lm_process_t]
```

# Description

Gets an `lm_process_t` from an `lm_thread_t`. It is especially useful when you want to interact with a specific thread of a process.

# Parameters

- pthr: valid `lm_thread_t` that will be used to find a process.

# Return Value

On success it returns a valid `lm_process_t`. On failure, it returns `None`.

