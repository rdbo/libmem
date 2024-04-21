# LM_CodeLengthEx

```c
LM_API lm_size_t LM_CALL
LM_CodeLengthEx(const lm_process_t *process,
		 lm_address_t        machine_code,
		 lm_size_t           min_length);
```

# Description
The function `LM_CodeLengthEx` calculates the size aligned to the instruction length, based on a minimum size, in a remote process.

# Parameters
 - `process`: The `process` parameter is a pointer to a valid process to get the aligned length from.
 - `machine_code`: The `machine_code` parameter is the address of the instructions in the remote process.
 - `min_length`: The `min_length` parameter is the minimum size to be aligned to instruction length.

# Return Value
On success, it returns the aligned size to the next instruction's length. On failure, it returns `0`.
