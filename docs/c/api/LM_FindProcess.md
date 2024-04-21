# LM_FindProcess

```c
LM_API lm_bool_t LM_CALL
LM_FindProcess(lm_string_t   process_name,
	       lm_process_t *process_out);
```

# Description
Searches for a process by name and returns whether the process was
found or not.

# Parameters
 - `process_name`: The name of the process you are trying to find
(e.g `game.exe`). It can also be a relative path, such as
`/game/hello` for a process at `/usr/share/game/hello`.
 - `process_out`: A pointer to the `lm_process_t` structure that will be
populated with information about the found process.

# Return Value
`LM_TRUE` if the process with the specified name was found
successfully or `LM_FALSE` otherwise.
