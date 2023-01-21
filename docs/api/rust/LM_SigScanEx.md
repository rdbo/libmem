# LM_SigScanEx

```rust
pub fn LM_SigScanEx(pproc : &lm_process_t, sig : &str, addr : lm_address_t, scansize : lm_size_t) -> Option<lm_address_t>
```

# Description

Searches for a byte signature in a memory region in a remote process.

# Parameters

- pproc: immutable reference to a valid process which will be scanned.
- sig: string representation of a byte signature that can contain unknown bytes (`??`). Example: `"E9 ?? ?? ?? ?? 90 90 90 90"`.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns `Some(address)`, where `address` is a valid `lm_address_t` containing the first match found. On failure, it returns `None`.

