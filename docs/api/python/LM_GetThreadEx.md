# LM_GetThreadEx

```python
def LM_GetThreadEx(pproc : lm_process_t : pproc : lm_process_t) -> Optional[None]:
```

# Description

Gets information about a thread in a remote process.

# Parameters

- pproc: valid process that will be searched for a thread

# Return Value

On success it returns a valid `lm_thread_t`. On failure, it returns `None`.

