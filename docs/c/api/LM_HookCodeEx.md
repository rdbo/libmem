# LM_HookCodeEx

```c
LM_API lm_size_t LM_CALL
LM_HookCodeEx(const lm_process_t *process,
	      lm_address_t        from,
	      lm_address_t        to,
	      lm_address_t       *trampoline_out);
```

# Description
The function places a hook/detour onto the address `from` in a remote process, redirecting it to the address `to`.
Optionally, it generates a trampoline in `trampoline_out` to call the original function in the remote process.

# Parameters
 - `process`: The remote process to place the hook in.
 - `from`: The address where the hook will be placed in the remote process.
 - `to`: The address where the hook will jump to in the remote process.
 - `trampoline_out`: Optional pointer to an `lm_address_t` variable that will receive a trampoline/gateway to call the
original function in the remote process.

# Return Value
The amount of bytes occupied by the hook (aligned to the nearest instruction) in the remote process.
