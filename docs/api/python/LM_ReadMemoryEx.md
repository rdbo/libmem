# LM_ReadMemory

```python
def LM_ReadMemoryEx(pproc : lm_process_t : pproc : lm_process_t, src : int : src : int, size : int : size : int) -> Optional[None]:
```

# Description

Reads `size` bytes of memory in the calling process from a virtual address (`src`).

# Parameters

- pproc: valid process which will be accessed for memory reading.
- src: the address which will be read `size` bytes from.
- size: the amount of bytes to read

# Return Value

On success, it returns a `bytearray` containing the bytes read, and its length should be equal to `size`. On failure, it returns `None`.

