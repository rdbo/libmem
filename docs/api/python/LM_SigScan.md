# LM_SigScan

```python
def LM_SigScan(sig : str, addr : int, scansize : int)
```

# Description

Searches for a byte signature in a memory region in the current process.

# Parameters

- sig: string representation of a byte signature that can contain unknown bytes (`??`). Example: `"E9 ?? ?? ?? ?? 90 90 90 90"`.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns a valid address (`int`) containing the first match found. On failure, it returns `None`.

