# VMT

```rust
impl lm_vmt_t {
    pub fn new(vtable : *mut lm_address_t) -> Self;

    pub fn hook(&mut self, index : lm_size_t, dst : lm_address_t);

    pub fn unhook(&mut self, index : lm_size_t);

    pub fn get_original(&self, index : lm_size_t) -> lm_address_t;

    pub fn reset(&mut self);
}
```

# Description

APIs to interact with Virtual Method Tables (VMTs) from OOP objects.

- `new`: Creates a new VMT manager from the VMT at `vtable`.
- `hook`: Hooks the VMT function at index `index`, changing it to `dst`.
- `unhook`: Unhooks the VMT function at index `index`.
- `reset`: Resets all the VMT functions back to their original addresses.

