# LM_SigScanEx

```c
LM_API lm_address_t LM_CALL
LM_SigScanEx(const lm_process_t *process,
	     lm_string_t         signature,
	     lm_address_t        address,
	     lm_size_t           scansize);
```

# Description
The function searches for a specific signature pattern in memory from a given process starting
from a specific address within a specified scan size.

# Parameters
 - `process`: The process whose memory will be scanned.
 - `signature`: The signature to be scanned for in memory. It is used to identify a specific
pattern of bytes in memory. You can use `??` to match against any byte, or the byte's hexadecimal
value. Example: `"DE AD BE EF ?? ?? 13 37"`.
 - `address`: The starting memory address where the signature scanning will begin. The function
will scan the memory starting from this address to find the pattern match.
 - `scansize`: The size of the memory region to scan starting from the `address` parameter. It
specifies the number of bytes to search for the signature pattern within the memory region.

# Return Value
The function retuns either the address of the pattern match found in the specified memory range
or `LM_ADDRESS_BAD` if no match is found (or an error occurs).
