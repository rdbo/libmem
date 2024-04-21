# LM_SigScanEx

```c
LM_API lm_address_t LM_CALL
LM_SigScanEx(const lm_process_t *process,
	     lm_string_t         signature,
	     lm_address_t        address,
	     lm_size_t           scansize);
```

# Description
The function `LM_SigScanEx` searches for a specific signature pattern in memory from a given process
starting from a specific address within a specified scan size.

# Parameters
 - `process`: The `process` parameter is a pointer to a structure representing a process in the
system. It's the process whose memory will be scanned.
 - `signature`: The `signature` parameter is a string representing the signature to be scanned for
in memory. It is used to identify a specific pattern of bytes in memory. You can use `??` to match
against any byte, or the byte's hexadecimal value. Example: `"DE AD BE EF ?? ?? 13 37"`.
 - `address`: The `address` parameter in the `LM_SigScanEx` function represents the starting address
in memory where the signature scanning will begin. This is the address from which the function will
start looking for a specific pattern defined by the `signature` parameter within the specified
`scansize`.
 - `scansize`: The `scansize` parameter in the `LM_SigScanEx` function represents the size of the
memory region to scan starting from the `address` parameter. It specifies the number of bytes to
search for the signature pattern within the memory region.

# Return Value
The function `LM_SigScanEx` is returning the memory address `match`, which is either the
address of the pattern match found in the specified memory range or `LM_ADDRESS_BAD` if no match is
found (or an error occurs).
