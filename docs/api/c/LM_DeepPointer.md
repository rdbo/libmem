# LM_DeepPointer

```c
LM_API lm_address_t LM_CALL
LM_DeepPointer(lm_address_t        base,
	       const lm_address_t *offsets,
	       size_t              noffsets)
```

# Description

Dereferences a deep pointer in the current process, generally result of a pointer scan or pointer map.

# Parameters

- base: the base address of the deep pointer
- offsets: the offsets that will be used to dereference and increment the base pointer
- noffsets: the number of offsets in the `offsets` array

# Return Value

On success, it returns a valid `lm_address_t`. On failure, it returns `LM_ADDRESS_BAD`.

