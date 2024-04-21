# LM_CodeLengthEx

```c
LM_API lm_size_t LM_CALL
LM_CodeLengthEx(const lm_process_t *process,
		 lm_address_t        machine_code,
		 lm_size_t           min_length);
```

# Description
The function calculates the size aligned to the instruction length, based on a minimum size, in a remote process.

# Parameters
 - `process`: The remote process to get the aligned length from.
 - `machine_code`: The address of the instructions in the remote process.
 - `min_length`: The minimum size to be aligned to instruction length.

# Return Value
On success, it returns the aligned size to the next instruction's length. On failure, it returns `0`.
