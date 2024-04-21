# LM_PatternScanEx

```c
LM_API lm_address_t LM_CALL
LM_PatternScanEx(const lm_process_t *process,
		 lm_bytearray_t      pattern,
		 lm_string_t         mask,
		 lm_address_t        address,
		 lm_size_t           scansize);
```

# Description
The function searches for a specific pattern in memory in a given process based on a mask.

# Parameters
 - `process`: The process whose memory will be scanned.
 - `pattern`: The pattern to be searched for in memory.
 - `mask`: The pattern mask used for scanning memory. It is used to specify which bytes in the
pattern should be matched against the memory content. The mask can contain characters such as
'?' which act as wildcards, allowing any byte to be matched. You can also use 'x' to have an exact
match.
 - `address`: The starting memory address where the scanning operation will begin. The function
will scan the memory starting from this address to find the pattern match.
 - `scansize`: The size of the memory region to scan starting from the specified `address`. It
determines the range within which the function will search for the specified pattern based on the
provided `pattern` and `mask`.

# Return Value
The function returns the memory address where a match for the given pattern and mask is
found within the specified scan size starting from the provided address. If no match is found or
if an error occurs, the function returns `LM_ADDRESS_BAD`.
