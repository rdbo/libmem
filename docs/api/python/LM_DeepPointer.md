# LM_DeepPointer

```python
def LM_DeepPointer(base: int, offsets: List[int]) -> Optional[int]
```

# Description

Dereferences a deep pointer in the current process, generally result of a pointer scan or pointer map.

# Parameters

- base: the base address of the deep pointer
- offsets: a list containing the offsets that will be used to dereference and increment the base pointer

# Return Value

On success, it returns a valid `lm_address_t`. On failure, it returns `None`.

