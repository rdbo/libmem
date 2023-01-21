# LM_PatternScanEx

```c
LM_API lm_address_t
LM_PatternScanEx(lm_process_t *pproc,
         lm_bytearr_t  pattern,
         lm_string_t   mask,
         lm_address_t  addr,
         lm_size_t     scansize);
```

# Description

Searches for specific bytes with a mask filter in a memory region in a remote process.

# Parameters

- pproc: pointer to a valid process which will be searched.
- pattern: the bytes to search for (it is common practice to leave unknown bytes as 0).
- mask: a mask filter to apply to the pattern. Use 'x' for a known byte and '?' for an unknown byte. Example: `"xxxx???x?xxx"`.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns the address of the first match found. On failure, it returns `LM_ADDRESS_BAD`.

