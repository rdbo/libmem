# LM_SetMemory

```python
def LM_SetMemory(dst : int, byte : bytes, size : int)
```

# Description

Sets `size` bytes of `dst` as `byte` in the calling process.

# Parameters

- dst: virtual address that will be set to `byte` for `size` bytes.
- byte: the byte to set `size` bytes of `dst` as.
- size: the amount of bytes to set

# Return Value

On success, it returns `true`. On failure, it returns `false`.

