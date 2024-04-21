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
The function `LM_PatternScanEx` searches for a specific pattern in memory in a given process
based on a mask.

# Parameters
 - `process`: The `process` parameter is a pointer to a structure representing a process in the
system. It's the process whose memory will be scanned.
 - `pattern`: The `pattern` parameter is an array of bytes that represents the pattern you are
searching for in memory.
 - `mask`: The `mask` parameter in the `LM_PatternScanEx` function is a string that represents the
pattern mask used for scanning memory. It is used to specify which bytes in the pattern should be
matched against the memory content. The mask can contain characters such as '?' which act as
wildcards, allowing any byte to be matched. You can also use 'x' to have an exact match.
 - `address`: The `address` parameter in the `LM_PatternScanEx` function represents the starting
address in memory where the pattern scanning will begin. The function will scan the memory starting
from this address to find the pattern match.
 - `scansize`: The `scansize` parameter in the `LM_PatternScanEx` function represents the size of the
memory region to scan starting from the specified `address`. It determines the range within which
the function will search for the specified pattern based on the provided `pattern` and `mask`.

# Return Value
The function `LM_PatternScanEx` returns an `lm_address_t` value, which represents the memory
address where a match for the given pattern and mask is found within the specified scan size
starting from the provided address. If no match is found or if an error occurs, the
function returns `LM_ADDRESS_BAD`.
