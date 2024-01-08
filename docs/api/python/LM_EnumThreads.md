# LM_EnumThreads

```python
def LM_EnumThreads() -> Optional[None]:
```

# Description

Enumerates all the threads in the calling process, returning them on a list.

#  Return Value

On success, it returns a `list` of `lm_thread_t` containing all valid threads. On failure, it returns `None`.

