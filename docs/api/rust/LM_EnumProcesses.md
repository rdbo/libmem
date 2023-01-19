# LM_EnumProcesses

```rust
pub fn LM_EnumProcesses() -> Option<Vec<lm_process_t>>
```

# Description

Enumerates all the current existing processes, returning them on a vector.

#  Return Value

Returns an `Option<Vec<lm_process_t>>`. On success, it is a `Some(process_list)` containing a vector with all processes; On failure, it is `None`.

