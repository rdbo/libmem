# LM_FreeMemoryEx

```python
def LM_FreeMemoryEx(pproc : lm_process_t, alloc : int, size : int)
```

# Description

Frees `size` bytes of allocated memory in a remote process.

# Parameters

- pproc: valid process which will have memory be deallocated.
- alloc: virtual address of the allocated memory.
- size: the size of the region to deallocate.

# Return Value

On success, it returns `true`. On failure, it returns `false`.

