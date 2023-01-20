# LM_UnloadModuleEx

```rust
pub fn LM_UnloadModuleEx(pproc : &lm_process_t, pmod : &lm_module_t) -> Option<()>
```

# Description

Unloads a module from a remote process.

# Parameters

- pproc: immutable reference to a valid process which the module will be unloaded from.
- pmod : immutable reference to a valid module that is loaded in the calling process

# Return Value

On success, it returns `Some(())`. On failure, it returns `None`.

