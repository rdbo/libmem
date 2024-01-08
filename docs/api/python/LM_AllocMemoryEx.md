# LM_AllocMemoryEx

```python
def LM_AllocMemoryEx(pproc: lm_process_t, size: int, prot: int) -> Optional[int]
```

# Description

Allocates `size` bytes of memory with protection flags `prot` in a remote process.

# Parameters

- pproc: valid process which will have memory be allocated.
- size: the size of the region to change the protection flags.
- prot: the protection flags (`LM_PROT_*`).

# Return Value

On success, it returns a valid `lm_address_t`. On failure, it returns `None`.

