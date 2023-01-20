# LM_SetMemoryEx

```python
def LM_SetMemoryEx(pproc : lm_process_t, dst : int, byte : bytes, size : int)
```

# Description

Sets `size` bytes of `dst` as `byte` in a remote process.

# Parameters

- pproc: valid process that will be accessed for writing memory.
- dst: virtual address that will be set to `byte` for `size` bytes.
- byte: the byte to set `size` bytes of `dst` as.
- size: the amount of bytes to set

# Return Value

On success, it returns `true`. On failure, it returns `false`.

