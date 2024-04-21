# LM_DeepPointerEx

```c
LM_API lm_address_t LM_CALL
LM_DeepPointerEx(const lm_process_t *process,
		 lm_address_t        base,
		 const lm_address_t *offsets,
		 lm_size_t           noffsets);
```

# Description
The function `LM_DeepPointerEx` calculates a deep pointer address by applying a series of offsets to a
base address and dereferencing intermediate pointers in a given process's memory space.

# Parameters
 - `process`: The `process` parameter is a pointer to a structure representing a process in the
system. It's the process that the deep pointer will be calculated from.
 - `base`: The `base` parameter in the `LM_DeepPointerEx` function represents the starting address
from which to calculate the deep pointer.
 - `offsets`: The `offsets` parameter is a pointer to an array of lm_address_t values. These values
are used as offsets to navigate through memory addresses in the `LM_DeepPointerEx` function.
 - `noffsets`: The `noffsets` parameter in the `LM_DeepPointerEx` function represents the number of
offsets in the `offsets` array. It indicates how many elements are in the array that contains the
offsets used to calculate the final memory address.

# Return Value
The function `LM_DeepPointerEx` returns a deep pointer calculated based on the provided base
address, offsets, and number of offsets. The function iterates through the offsets, adjusting the
base address and dereferencing accordingly.
