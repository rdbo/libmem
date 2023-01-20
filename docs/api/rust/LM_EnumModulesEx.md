# LM_EnumModulesEx

```rust
pub fn LM_EnumModulesEx(pproc : &lm_process_t) -> Option<Vec<lm_module_t>>
```

# Description

Enumerates all the modules in a remote process, returning them on a vector.

#  Return Value

On success, it returns a `Some(module_list)`, where `module_list` is a vector containing all valid modules; On failure, it returns `None`.

