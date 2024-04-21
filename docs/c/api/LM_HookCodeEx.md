# LM_HookCodeEx

```c
LM_API lm_size_t LM_CALL
LM_HookCodeEx(const lm_process_t *process,
	      lm_address_t        from,
	      lm_address_t        to,
	      lm_address_t       *trampoline_out);
```

# Description
The function `LM_HookCodeEx` places a hook/detour onto the address `from` in a remote process, redirecting it to the address `to`.
Optionally, it generates a trampoline in `trampoline_out` to call the original function in the remote process.

# Parameters
 - `process`: The `process` parameter is a pointer to a valid process to place the hook in.
 - `from`: The `from` parameter is the address where the hook will be placed in the remote process.
 - `to`: The `to` parameter is the address where the hook will jump to in the remote process.
 - `trampoline_out`: Optional pointer to an `lm_address_t` variable that will receive a trampoline/gateway to call the
original function in the remote process.

# Return Value
On success, it returns the amount of bytes occupied by the hook (aligned to the nearest instruction) in the remote process.
On failure, it returns `0`.
