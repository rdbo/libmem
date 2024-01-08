# LM_DeepPointerEx

```c
LM_API lm_address_t LM_CALL
LM_DeepPointerEx(const lm_process_t *pproc,
		 lm_address_t        base,
		 const lm_address_t *offsets,
		 lm_size_t           noffsets)
```

# Description

Dereferences a deep pointer in a remote process, generally result of a pointer scan or pointer map.

# Parameters

- pproc: pointer to a valid process where the pointer will be resolved
- base: the base address of the deep pointer
- offsets: the offsets that will be used to dereference and increment the base pointer
- noffsets: the number of offsets in the `offsets` array

# Return Value

On success, it returns a valid `lm_address_t`. On failure, it returns `LM_ADDRESS_BAD`.

