# LM_ReadMemory

```python
def LM_ReadMemory(src: int, size: int) -> Optional[bytearray]
```

# Description

Reads `size` bytes of memory in the calling process from a virtual address (`src`).

# Parameters

- src: the address which will be read `size` bytes from.
- size: the amount of bytes to read

# Return Value

On success, it returns a `bytearray` containing the bytes read, and its length should be equal to `size`. On failure, it returns `None`.

