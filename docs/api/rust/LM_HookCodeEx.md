# LM_HookCodeEx

```rust
pub fn LM_HookCodeEx(pproc : &lm_process_t, from : lm_address_t, to : lm_address_t) -> Option<(lm_address_t, lm_size_t)>
```

# Description

Places a hook/detour onto the address `from`, redirecting it to the address `to` in a remote process. It returns a trampoline and the hook size; the trampoline can be used to call the original function.

# Parameters

- pproc: immutable reference to a valid process where the hook will be placed.
- from: the address where the hook will be placed.
- to: the address where the hook will jump to.

# Return Value

On success, it returns `Some((trampoline_address, hook_size))`, where `trampoline_address` is an `lm_address_t` where there is a trampoline/gateway that you can use to call the original function; `size` is the amount of bytes occupied by the hook (aligned to the nearest instruction). On failure, it returns `None`.

