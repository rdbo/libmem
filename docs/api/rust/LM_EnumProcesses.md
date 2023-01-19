# LM_EnumProcesses

```rust
pub fn LM_EnumProcesses() -> Option<Vec<lm_process_t>>
```

# Description

Enumerates all the current existing processes, returning them on a vector.

#  Return Value

On success, it returns a `Some(process_list)`, where `process_list` is a vector containing all valid processes; On failure, it returns `None`.

