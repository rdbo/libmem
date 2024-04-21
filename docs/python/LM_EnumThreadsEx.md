# LM_EnumThreads

```python
def LM_EnumThreadsEx(pproc: lm_process_t) -> Optional[List[lm_thread_t]]
```

# Description

Enumerates all the threads in a remote process, returning them on a list.

# Parameters

- pproc: valid process that will be searched for threads.

#  Return Value

On success, it returns a `list` of `lm_thread_t` containing all valid threads. On failure, it returns `None`.

