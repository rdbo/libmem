# LM_IsProcessAlive

```rust
pub fn LM_IsProcessAlive(pproc : &lm_process_t) -> bool
```

# Description

Checks if a process is alive or not

# Parameters

- pproc: immutable reference to a valid `lm_process_t` variable that will be used to check the process state

# Return Value

It returns `true` is the process is alive, and `false` if the process is dead.

