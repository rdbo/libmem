# LM_PatternScan

```rust
pub unsafe fn LM_PatternScan(pattern : &[u8], mask : &str, addr : lm_address_t, scansize : lm_size_t) -> Option<lm_address_t>
```

# Description

Searches for specific bytes with a mask filter in a memory region in the current process.

# Parameters

- pattern: the bytes to search for (it is common practice to leave unknown bytes as 0).
- mask: a mask filter to apply to the pattern. Use 'x' for a known byte and '?' for an unknown byte. Example: `"xxxx???x?xxx"`.
- addr: the address to start the scan from.
- scansize: the maximum size of the scan, in bytes.

# Return Value

On success, it returns `Some(address)`, where `address` is a valid `lm_address_t` containing the first match found. On failure, it returns `None`.

