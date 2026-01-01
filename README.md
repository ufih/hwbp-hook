# hwbp-hook

Uses CPU debug registers (DR0-DR3) to intercept function execution without modifying memory.

## Features

- 4 simultaneous hooks (hardware limit)
- Runtime enable/disable without reinstalling
- Change target address on the fly
- Swap callbacks and arguments dynamically
- Thread-safe
- Zero memory modification

## How It Works

The x86/x64 architecture provides 4 debug address registers (DR0-DR3) that can trigger exceptions when certain addresses are accessed. When you set a breakpoint on an address and that address executes, the CPU raises EXCEPTION_SINGLE_STEP before running the instruction.[web:132][web:139]

This library:
1. Sets debug registers via SetThreadContext using CONTEXT_DEBUG_REGISTERS.[web:141]
2. Catches EXCEPTION_SINGLE_STEP with a vectored exception handler.
3. Identifies which breakpoint fired using the DR6 status register (bits B0–B3).[web:136]
4. Calls your callback with full CPU context.
5. Sets the Resume Flag in EFLAGS so execution continues past the breakpoint instead of looping on the same instruction.[web:136][web:139]

Debug registers are per-thread, so the library enumerates all threads and applies breakpoints to each one.

## Build

```c
    gcc -Wall -O2 -Iinclude -o hwbp_hook.exe src/main.c src/hwbp.c -lpsapi
```

For 32-bit builds, add `-m32` and use a 32-bit toolchain.

## API

### Initialization

```c
bool hwbp_init(void);
```

Initializes the library and registers the exception handler. Called automatically by `hwbp_set()` if needed.

Returns true on success.

```c
void hwbp_shutdown(void);
```

Removes all hooks and cleans up. Call before exit.

### Installing Hooks

```c
int hwbp_set(void *addr, hwbp_fn fn, void *arg);
```

Installs a hook at `addr`. When execution reaches that address, `fn` is called with `arg`.

Returns slot number (0-3) on success, -1 if all slots are occupied.

Example:

```c
    void *target = hwbp_resolve("kernel32.dll", "CreateFileW");
    int slot = hwbp_set(target, my_callback, NULL);
```

### Removing Hooks

```c
void hwbp_del(int slot);
```

Removes the hook in slot `slot`.

```c
void hwbp_del_addr(void *addr);
```

Removes the hook at address `addr`.

```c
void hwbp_clear(void);
```

Removes all hooks.

### Runtime Control

```c
void hwbp_on(int slot);
```

Enables a disabled hook without reinstalling.

```c
void hwbp_off(int slot);
```

Temporarily disables a hook without removing it. The slot remains occupied.

```c
void hwbp_retarget(int slot, void *addr);
```

Changes the target address of an existing hook. Useful for redirecting to a different function.

```c
void hwbp_refn(int slot, hwbp_fn fn);
```

Changes the callback function.

```c
void hwbp_rearg(int slot, void *arg);
```

Changes the user argument passed to the callback.

### Queries

```c
int hwbp_slot(void *addr);
```

Finds the slot number for a given address. Returns -1 if not found.

```c
void *hwbp_addr(int slot);
```

Returns the address hooked in slot, or NULL if inactive.

```c
bool hwbp_enabled(int slot);
```

Returns true if the hook is active and enabled.

```c
int hwbp_count(void);
```

Returns the number of active hooks (0-4).

### Thread Management

```c
void hwbp_sync(DWORD tid);
```

Applies all active hooks to thread `tid`. Call this after creating a new thread.

```c
void hwbp_sync_all(void);
```

Reapplies all hooks to all threads. Use after making runtime modifications to ensure consistency.

### Utility

```c
void *hwbp_resolve(const char *mod, const char *fn);
```

Resolves a function address by module and function name. Loads the module if not already loaded.

Example:

```c
    void *addr = hwbp_resolve("user32.dll", "MessageBoxA");
```

## Callback Function

Your callback receives full CPU context and must return an action.

```c
typedef hwbp_action_t (*hwbp_fn)(PCONTEXT ctx, void *arg);
```

### Context Access

The `PCONTEXT ctx` parameter gives you access to all registers at the moment the breakpoint triggers.[web:141]

Arguments (x64 fastcall):

```c
  ctx->Rcx    // 1st argument
  ctx->Rdx    // 2nd argument
  ctx->R8     // 3rd argument
  ctx->R9     // 4th argument
  // Stack arguments start at ctx->Rsp + 0x28
```

Other useful registers:

```c
  ctx->Rax    // return value (on function exit)
  ctx->Rip    // instruction pointer
  ctx->Rsp    // stack pointer
```

On x86 (cdecl/stdcall), arguments are on the stack:

```c
  // return address at *(DWORD *)ctx->Esp
  // 1st argument at *(DWORD *)(ctx->Esp + 0x04)
  // 2nd argument at *(DWORD *)(ctx->Esp + 0x08)
  // 3rd argument at *(DWORD *)(ctx->Esp + 0x0C)
  ctx->Eax    // return value
  ctx->Eip    // instruction pointer
  ctx->Esp    // stack pointer
```

You can read and modify any of these.

### Return Values

```c
HWBP_CONTINUE   // Execute the original instruction normally
HWBP_SKIP       // Skip the instruction (you must adjust Eip/Rip)
HWBP_REDIRECT   // Eip/Rip was changed, jump there
```

## Examples

### Basic Hook

```c
    hwbp_action_t on_messagebox(PCONTEXT ctx, void *arg)
    {
        (void)arg;

        const char *text = (const char *)ctx->Rdx;
        printf("MessageBoxA called with text: %s\n", text);
        return HWBP_CONTINUE;
    }

    int main(void)
    {
        hwbp_init();
        
        void *addr = hwbp_resolve("user32.dll", "MessageBoxA");
        hwbp_set(addr, on_messagebox, NULL);
        
        MessageBoxA(NULL, "Test", "Title", MB_OK);
        
        hwbp_shutdown();
        return 0;
    }
```

### Modify Arguments

```c
    hwbp_action_t redirect_file(PCONTEXT ctx, void *arg)
    {
        (void)arg;

        wchar_t *path = (wchar_t *)ctx->Rcx;
        
        if (wcsstr(path, L"secret.txt"))
        {
            ctx->Rcx = (DWORD64)L"C:\\allowed.txt";
        }
        
        return HWBP_CONTINUE;
    }
```

### Block Execution

```c
    hwbp_action_t block_exit(PCONTEXT ctx, void *arg)
    {
        (void)arg;

        /* Fake a successful return without calling the function */
        ctx->Rax = 1;
        ctx->Rip = *(DWORD64 *)ctx->Rsp;  /* return address */
        ctx->Rsp += 8;                    /* pop return address */
        return HWBP_SKIP;
    }
```

### Runtime Modification

```c
    int slot = hwbp_set(func_a, callback_a, NULL);

    /* Later: redirect to different function */
    hwbp_retarget(slot, func_b);

    /* Change callback */
    hwbp_refn(slot, callback_b);

    /* Temporarily disable */
    hwbp_off(slot);

    /* Re-enable */
    hwbp_on(slot);
```

### New Thread Support

```c
    DWORD WINAPI worker_thread(LPVOID param)
    {
        (void)param;

        /* Apply hooks to this thread */
        hwbp_sync(GetCurrentThreadId());
        
        /* Now hooks are active here */
        return 0;
    }
```

## Limitations

- Maximum 4 hooks (CPU has 4 debug registers)
- Windows only
- Debug registers are per-thread (new threads need hwbp_sync)
- Vectored exception handler registration is visible to other code
- Debug registers can be read/cleared by other code using GetThreadContext/SetThreadContext[web:132][web:135]

## Notes

The Resume Flag (bit 16 of EFLAGS) is critical. After a debug exception, the CPU will keep triggering on the same instruction unless you either:

1. Set the Resume Flag (what this library does for HWBP_CONTINUE).  
2. Change Eip/Rip to point elsewhere.  
3. Clear the debug registers (DR0-DR3/DR7).[web:136][web:139]

This library handles that bookkeeping for you based on your callback’s return value.

## License

MIT
