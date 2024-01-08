# LM_FreeMemory

```python
def LM_FreeMemory(alloc : int : alloc : int, size : int : size : int) -> Optional[None]:
```

# Description

Frees `size` bytes of allocated memory in the calling process.

# Parameters

- alloc: virtual address of the allocated memory.
- size: the size of the region to deallocate.

# Return Value

On success, it returns `true`. On failure, it returns `false`.

