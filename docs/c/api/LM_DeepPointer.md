# LM_DeepPointer

```c
LM_API lm_address_t LM_CALL
LM_DeepPointer(lm_address_t        base,
	       const lm_address_t *offsets,
	       size_t              noffsets);
```

# Description
The function `LM_DeepPointer` calculates a deep pointer address by applying a series of offsets to a
base address and dereferencing intermediate pointers.

# Parameters
 - `base`: The `base` parameter in the `LM_DeepPointer` function represents the starting address
from which to calculate the deep pointer.
 - `offsets`: The `offsets` parameter is a pointer to an array of lm_address_t values. These values
are used as offsets to navigate through memory addresses in the `LM_DeepPointer` function.
 - `noffsets`: The `noffsets` parameter in the `LM_DeepPointer` function represents the number of
offsets in the `offsets` array. It indicates how many elements are in the array that contains the
offsets used to calculate the final memory address.

# Return Value
The function `LM_DeepPointer` returns a deep pointer calculated based on the provided base
address, offsets, and number of offsets. The function iterates through the offsets, adjusting the
base address and dereferencing accordingly.
