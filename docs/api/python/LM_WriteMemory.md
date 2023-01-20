# LM_WriteMemory

```python
def LM_WriteMemory(dst : int, src : bytearray)
```

# Description

Writes `src` in the calling process into a virtual address (`dst`).

# Parameters

- dst: the address which will be written the bytes from `src`.
- src: the bytes to write into `dst`.

# Return Value

On success, it returns `true`. On failure, it returns `false`.

