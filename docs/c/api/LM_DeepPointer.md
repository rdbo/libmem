# LM_DeepPointer

```c
LM_API lm_address_t LM_CALL
LM_DeepPointer(lm_address_t        base,
	       const lm_address_t *offsets,
	       size_t              noffsets);
```

# Description
The function calculates a deep pointer address by applying a series of
offsets to a base address and dereferencing intermediate pointers.

# Parameters
 - `base`: The starting address from which to calculate the deep pointer.
 - `offsets`: An array of offsets used to navigate through the memory addresses.
 - `noffsets`: The number of offsets in the `offsets` array.

# Return Value
The function returns a deep pointer calculated based on the provided
base address, offsets, and number of offsets. The function iterates through
the offsets, adjusting the base address and dereferencing accordingly.
