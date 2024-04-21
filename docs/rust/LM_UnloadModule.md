# LM_UnloadModule

```rust
pub fn LM_UnloadModule(pmod : &lm_module_t) -> Option<()>
```

# Description

Unloads a module from the calling process.

# Parameters

- pmod : immutable reference to a valid module that is loaded in the calling process

# Return Value

On success, it returns `Some(())`. On failure, it returns `None`.

