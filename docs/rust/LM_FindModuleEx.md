# LM_FindModuleEx

```rust
pub fn LM_FindModuleEx(pproc : &lm_process_t, name : &str) -> Option<lm_module_t>
```

# Description

Searches for a module in a remote process based on it's name or path.

# Parameters

- pproc: immutable reference to a valid process that will be searched for the module.
- name: string containing the name of the module, such as `"gamemodule.dll"` or `"gamemodule.so"`. It may also be a relative/absolute path, like `"bin/lib/gamemodule.dll"`, or `"/usr/lib/libc.so"`.

# Return Value

On success, it returns `Some(module)`, where `module` is a valid `lm_module_t`. On failure, it returns `None`.

