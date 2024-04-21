# LM_AllocMemory

```python
def LM_AllocMemory(size: int, prot: int) -> Optional[int]
```

# Description

Allocates `size` bytes of memory with protection flags `prot` in the calling process.

# Parameters

- size: the size of the region to change the protection flags.
- prot: the protection flags (`LM_PROT_*`).

# Return Value

On success, it returns a valid `lm_address_t`. On failure, it returns `None`.

