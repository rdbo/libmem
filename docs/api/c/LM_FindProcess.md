# LM_FindProcessEx

```c
LM_API lm_bool_t
LM_FindProcess(lm_string_t   procstr,
	       lm_process_t *procbuf);
```

# Description

Searches for a process based on it's name or path

# Parameters

- procstr: string containing the name of the process, such as `"test1.exe"` or `"dwm"`. It may also be a relative/absolute path, like `"mygame/game.exe"`, or `"/usr/bin/bash"`
- procbuf: pointer to an `lm_process_t` variable that will receive the process information

# Return Value

On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.

