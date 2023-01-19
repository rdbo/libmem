# LM_FindProcessEx

```rust
pub fn LM_FindProcess(procstr : &str) -> Option<lm_process_t>
```

# Description

Searches for a process based on it's name or path

# Parameters

- procstr: string containing the name of the process, such as `"test1.exe"` or `"dwm"`. It may also be a relative/absolute path, like `"mygame/game.exe"`, or `"/usr/bin/bash"`

# Return Value

On success, it returns `Some(process)`, where `process` is a valid `lm_process_t`. On failure, it returns `None`.

