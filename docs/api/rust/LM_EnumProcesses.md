# LM_EnumProcesses

```rust
pub fn LM_EnumProcesses() -> Vec<lm_process_t>;
```

# Description

Enumerates all the current existing processes, returning them on a vector.

#  Return Value

Returns a `Vec<lm_process_t>` containing a list of all processes, or an empty vector on failure.

