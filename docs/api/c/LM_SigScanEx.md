# LM_SigScanEx

```c
LM_API lm_address_t
LM_SigScanEx(lm_process_t *pproc,
         lm_string_t   sig,
         lm_address_t  addr,
         lm_size_t     scansize);
```

# Description

Searches for a byte signature in a memory region in a remote process.

# Parameters

- pproc: pointer to a valid process which will be searched.
- sig: string representation of a byte signature that can contain unknown bytes (`??`). Example: `"E9 ?? ?? ?? ?? 90 90 90 90"`.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns the address of the first match found. On failure, it returns `LM_ADDRESS_BAD`.

