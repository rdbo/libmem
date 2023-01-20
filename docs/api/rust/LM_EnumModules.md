# LM_EnumModules

```rust
pub fn LM_EnumModules() -> Option<Vec<lm_module_t>>
```

# Description

Enumerates all the modules in the calling processes, returning them on a vector.

#  Return Value

On success, it returns a `Some(module_list)`, where `module_list` is a vector containing all valid modules; On failure, it returns `None`.

