# LM_SigScanEx

```python
def LM_SigScanEx(pproc : lm_process_t, sig : str, addr : int, scansize : int)
```

# Description

Searches for a byte signature in a memory region in a remote process.

# Parameters

- pproc: valid process which will be searched.
- sig: string representation of a byte signature that can contain unknown bytes (`??`). Example: `"E9 ?? ?? ?? ?? 90 90 90 90"`.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns a valid address (`int`) containing the first match found. On failure, it returns `None`.

