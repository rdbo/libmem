# LM_CodeLength

```c
LM_API lm_size_t LM_CALL
LM_CodeLength(lm_address_t machine_code,
	      lm_size_t    min_length);
```

# Description
The function calculates the size aligned to the instruction length, based on a minimum size.

# Parameters
 - `machine_code`: The address of the instructions.
 - `min_length`: The minimum size to be aligned to instruction length.

# Return Value
On success, it returns the aligned size to the next instruction's length. On failure, it returns `0`.
