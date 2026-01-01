/*
 * hwbp.c - Hardware Breakpoint Hooking Implementation
 *
 * Implements the runtime for managing hardware breakpoint hooks on Windows.
 * Uses DR0–DR3 for addresses, DR6 for status, and DR7 for control.[web:132][web:136]
 */

#include "hwbp.h"
#include <TlHelp32.h>
#include <string.h>

/*
 * Architecture detection.
 * Thanks to https://github.com/EvilBytecode for telling me to add x86 support.
 *
 * The debug registers exist on both x86 and x64, but the CONTEXT register
 * fields and pointer sizes differ.[web:132][web:141]
 *
 * We abstract the debug register and control values via hwbp_reg_t.
 */
#if defined(_M_X64) || defined(__x86_64__)
    #define HWBP_ARCH_X64
    typedef DWORD64 hwbp_reg_t;
#elif defined(_M_IX86) || defined(__i386__)
    #define HWBP_ARCH_X86
    typedef DWORD hwbp_reg_t;
#else
    #error "Unsupported architecture: only x86/x64 are supported."
#endif

/*
 * Internal hook state structure.
 *
 * Each hook corresponds to one hardware breakpoint slot (DR0–DR3).
 */
typedef struct
{
    void    *addr;      /* Target address for breakpoint */
    hwbp_fn  fn;        /* User callback function */
    void    *arg;       /* User argument passed to callback */
    bool     active;    /* Slot in use */
    bool     enabled;   /* Breakpoint applied to threads */

} hook_t;

/*
 * Global context containing all hooks and vectored exception handler state.
 */
static struct
{
    hook_t           hooks[4];  /* Four hardware breakpoint slots */
    PVOID            veh;       /* Vectored exception handler handle */
    CRITICAL_SECTION lock;      /* Global lock for thread safety */
    bool             ready;     /* Initialization flag */

} ctx = { 0 };

/*
 * Enable a breakpoint in DR7.
 *
 * DR7 layout (per slot i):[web:136]
 *   - Bit (i*2):   local enable
 *   - Bit (i*2+1): global enable (unused here)
 *   - Bits 16+4*i..19+4*i: type/length (we clear these, leaving 00: execute, 1 byte)
 */
static hwbp_reg_t
dr7_enable(hwbp_reg_t dr7, int slot)
{
    /*
     * Enable local breakpoint for this slot.
     * For slot i, local enable is bit 2*i.[web:136]
     */
    dr7 |= (1ULL << (slot * 2));

    /*
     * Clear existing condition and length bits for this slot (4 bits).
     * Bits 16+4*i..19+4*i are R/W length + condition.[web:136]
     */
    dr7 &= ~(0x0FULL << (16 + slot * 4));

    /*
     * Condition = 00 (execute), length = 00 (1 byte) is left at zero.
     */
    return dr7;
}

/*
 * Disable a breakpoint in DR7.
 */
static hwbp_reg_t
dr7_disable(hwbp_reg_t dr7, int slot)
{
    /* Disable local breakpoint (clear 2*i). */
    dr7 &= ~(1ULL << (slot * 2));

    /* Clear condition and length for this slot. */
    dr7 &= ~(0x0FULL << (16 + slot * 4));

    return dr7;
}

/*
 * Write a value to one of the debug address registers (DR0–DR3).
 */
static void
write_dr(PCONTEXT c, int slot, hwbp_reg_t value)
{
    switch (slot)
    {
        case 0: c->Dr0 = value; break;
        case 1: c->Dr1 = value; break;
        case 2: c->Dr2 = value; break;
        case 3: c->Dr3 = value; break;
        default:
            break;
    }
}

/*
 * Get the current instruction pointer (Eip or Rip) as a void*.
 */
static void *
get_ip(PCONTEXT c)
{
#ifdef HWBP_ARCH_X64
    return (void *)c->Rip;
#else
    return (void *)c->Eip;
#endif
}

/*
 * Apply or clear a breakpoint on a specific thread.
 *
 * Parameters:
 *   tid    - Thread ID.
 *   slot   - Debug register slot (0–3).
 *   addr   - Breakpoint address (ignored if enable == false).
 *   enable - true to set breakpoint, false to clear.
 */
static void
apply_to_thread(DWORD tid, int slot, void *addr, bool enable)
{
    HANDLE thread      = NULL;
    bool   need_close  = false;

    /*
     * If it's the current thread, use GetCurrentThread().
     * Otherwise open a handle with sufficient rights to manipulate context.[web:138]
     */
    if (tid == GetCurrentThreadId())
    {
        thread = GetCurrentThread();
    }
    else
    {
        thread = OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            FALSE,
            tid
        );

        if (!thread)
            return;

        need_close = true;
        SuspendThread(thread);
    }

    /* Only modify debug registers (CONTEXT_DEBUG_REGISTERS). */
    CONTEXT c;
    memset(&c, 0, sizeof(c));
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(thread, &c))
    {
        write_dr(&c, slot, enable ? (hwbp_reg_t)addr : 0);
        c.Dr7 = enable ? dr7_enable(c.Dr7, slot) : dr7_disable(c.Dr7, slot);
        c.Dr6 = 0;  /* Clear status register so stale flags don't leak.[web:142] */

        SetThreadContext(thread, &c);
    }

    if (need_close)
    {
        ResumeThread(thread);
        CloseHandle(thread);
    }
}

/*
 * Apply or clear a breakpoint on all threads in the current process.
 *
 * Uses a thread snapshot to enumerate threads via ToolHelp32.[web:132][web:139]
 */
static void
apply_to_all_threads(int slot, void *addr, bool enable)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 entry;
    memset(&entry, 0, sizeof(entry));
    entry.dwSize = sizeof(entry);

    DWORD pid = GetCurrentProcessId();

    if (Thread32First(snapshot, &entry))
    {
        do
        {
            if (entry.th32OwnerProcessID == pid)
                apply_to_thread(entry.th32ThreadID, slot, addr, enable);

        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

/*
 * Vectored Exception Handler.
 *
 * Catches EXCEPTION_SINGLE_STEP, checks DR6 to find which breakpoint fired,
 * verifies the IP matches the expected address, and then calls the user
 * callback for that hook.[web:132][web:139][web:136]
 */
static LONG CALLBACK
exception_handler(PEXCEPTION_POINTERS info)
{
    /* Only process single-step exceptions triggered by debug registers. */
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT c = info->ContextRecord;

    EnterCriticalSection(&ctx.lock);

    /*
     * DR6 bits B0..B3 indicate which debug event fired.[web:136]
     * We iterate all four possible slots and handle only the ones we own.
     */
    for (int i = 0; i < 4; i++)
    {
        /* Check if this breakpoint triggered (DR6 bit i set). */
        if (!(c->Dr6 & (1 << i)))
            continue;

        hook_t *hook = &ctx.hooks[i];

        /* Skip inactive or disabled hooks. */
        if (!hook->active || !hook->enabled)
            continue;

        /* Ensure the current instruction pointer is exactly the hook address. */
        if (hook->addr != get_ip(c))
            continue;

        /* Clear the status bit B[i] in DR6 to avoid stale flags. */
        c->Dr6 &= ~(1ULL << i);

        /* Call user callback outside of any further iteration logic. */
        hwbp_action_t action = HWBP_CONTINUE;

        if (hook->fn)
            action = hook->fn(c, hook->arg);

        LeaveCriticalSection(&ctx.lock);

        /*
         * For HWBP_CONTINUE:
         *   Set Resume Flag (RF, bit 16 of EFLAGS) to disable further
         *   single-step exceptions on the very next instruction.[web:136][web:139]
         *
         * For HWBP_SKIP / HWBP_REDIRECT:
         *   Caller manipulates Eip/Rip; we just continue execution.
         */
        if (action == HWBP_CONTINUE)
            c->EFlags |= 0x10000;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    LeaveCriticalSection(&ctx.lock);
    return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * Initialize global context and register the vectored exception handler.
 */
bool
hwbp_init(void)
{
    if (ctx.ready)
        return true;

    memset(&ctx, 0, sizeof(ctx));
    InitializeCriticalSection(&ctx.lock);

    /*
     * Register the vectored exception handler with priority 1.
     * This gives it a chance to run before most user handlers.[web:132]
     */
    ctx.veh = AddVectoredExceptionHandler(1, exception_handler);

    if (!ctx.veh)
    {
        DeleteCriticalSection(&ctx.lock);
        return false;
    }

    ctx.ready = true;
    return true;
}

/*
 * Shutdown the library: remove hooks and unregister the handler.
 */
void
hwbp_shutdown(void)
{
    if (!ctx.ready)
        return;

    /* Remove all hooks and clear debug registers. */
    hwbp_clear();

    /* Unregister vectored exception handler. */
    if (ctx.veh)
        RemoveVectoredExceptionHandler(ctx.veh);

    DeleteCriticalSection(&ctx.lock);
    ctx.ready = false;
}

/*
 * Install a hardware breakpoint hook in the first free slot.
 */
int
hwbp_set(void *addr, hwbp_fn fn, void *arg)
{
    if (!ctx.ready && !hwbp_init())
        return -1;

    EnterCriticalSection(&ctx.lock);

    /* Find a free slot. */
    int slot = -1;

    for (int i = 0; i < 4; i++)
    {
        if (!ctx.hooks[i].active)
        {
            slot = i;
            break;
        }
    }

    if (slot >= 0)
    {
        ctx.hooks[slot].addr    = addr;
        ctx.hooks[slot].fn      = fn;
        ctx.hooks[slot].arg     = arg;
        ctx.hooks[slot].active  = true;
        ctx.hooks[slot].enabled = true;
    }

    LeaveCriticalSection(&ctx.lock);

    /* Apply to all threads if a slot was obtained. */
    if (slot >= 0)
        apply_to_all_threads(slot, addr, true);

    return slot;
}

/*
 * Remove a hook by slot index.
 */
void
hwbp_del(int slot)
{
    if (slot < 0 || slot > 3 || !ctx.ready)
        return;

    EnterCriticalSection(&ctx.lock);

    if (!ctx.hooks[slot].active)
    {
        LeaveCriticalSection(&ctx.lock);
        return;
    }

    ctx.hooks[slot].active  = false;
    ctx.hooks[slot].enabled = false;

    LeaveCriticalSection(&ctx.lock);

    /* Clear from all threads. */
    apply_to_all_threads(slot, NULL, false);
}

/*
 * Remove a hook by address.
 */
void
hwbp_del_addr(void *addr)
{
    int slot = hwbp_slot(addr);

    if (slot >= 0)
        hwbp_del(slot);
}

/*
 * Remove all hooks.
 */
void
hwbp_clear(void)
{
    for (int i = 0; i < 4; i++)
        hwbp_del(i);
}

/*
 * Enable a previously disabled hook.
 */
void
hwbp_on(int slot)
{
    if (slot < 0 || slot > 3)
        return;

    EnterCriticalSection(&ctx.lock);

    hook_t *hook = &ctx.hooks[slot];

    if (!hook->active || hook->enabled)
    {
        LeaveCriticalSection(&ctx.lock);
        return;
    }

    hook->enabled = true;
    void *addr = hook->addr;

    LeaveCriticalSection(&ctx.lock);

    apply_to_all_threads(slot, addr, true);
}

/*
 * Disable a hook without removing it.
 */
void
hwbp_off(int slot)
{
    if (slot < 0 || slot > 3)
        return;

    EnterCriticalSection(&ctx.lock);

    hook_t *hook = &ctx.hooks[slot];

    if (!hook->active || !hook->enabled)
    {
        LeaveCriticalSection(&ctx.lock);
        return;
    }

    hook->enabled = false;

    LeaveCriticalSection(&ctx.lock);

    apply_to_all_threads(slot, NULL, false);
}

/*
 * Change the target address of an existing hook.
 */
void
hwbp_retarget(int slot, void *addr)
{
    if (slot < 0 || slot > 3)
        return;

    EnterCriticalSection(&ctx.lock);

    hook_t *hook = &ctx.hooks[slot];

    if (!hook->active)
    {
        LeaveCriticalSection(&ctx.lock);
        return;
    }

    hook->addr = addr;
    bool enabled = hook->enabled;

    LeaveCriticalSection(&ctx.lock);

    /* Reapply if currently enabled. */
    if (enabled)
        apply_to_all_threads(slot, addr, true);
}

/*
 * Change the callback function of an existing hook.
 */
void
hwbp_refn(int slot, hwbp_fn fn)
{
    if (slot < 0 || slot > 3)
        return;

    EnterCriticalSection(&ctx.lock);

    if (ctx.hooks[slot].active)
        ctx.hooks[slot].fn = fn;

    LeaveCriticalSection(&ctx.lock);
}

/*
 * Change the user argument of an existing hook.
 */
void
hwbp_rearg(int slot, void *arg)
{
    if (slot < 0 || slot > 3)
        return;

    EnterCriticalSection(&ctx.lock);

    if (ctx.hooks[slot].active)
        ctx.hooks[slot].arg = arg;

    LeaveCriticalSection(&ctx.lock);
}

/*
 * Find the slot index for a given address.
 */
int
hwbp_slot(void *addr)
{
    EnterCriticalSection(&ctx.lock);

    for (int i = 0; i < 4; i++)
    {
        if (ctx.hooks[i].active && ctx.hooks[i].addr == addr)
        {
            LeaveCriticalSection(&ctx.lock);
            return i;
        }
    }

    LeaveCriticalSection(&ctx.lock);
    return -1;
}

/*
 * Get the target address for a slot.
 */
void *
hwbp_addr(int slot)
{
    if (slot < 0 || slot > 3)
        return NULL;

    return ctx.hooks[slot].active ? ctx.hooks[slot].addr : NULL;
}

/*
 * Check if a slot is active and enabled.
 */
bool
hwbp_enabled(int slot)
{
    if (slot < 0 || slot > 3)
        return false;

    return ctx.hooks[slot].active && ctx.hooks[slot].enabled;
}

/*
 * Get the number of active hooks.
 */
int
hwbp_count(void)
{
    int count = 0;

    for (int i = 0; i < 4; i++)
    {
        if (ctx.hooks[i].active)
            count++;
    }

    return count;
}

/*
 * Apply all active hooks to a specific thread.
 */
void
hwbp_sync(DWORD tid)
{
    EnterCriticalSection(&ctx.lock);

    for (int i = 0; i < 4; i++)
    {
        hook_t *hook = &ctx.hooks[i];

        if (hook->active && hook->enabled)
            apply_to_thread(tid, i, hook->addr, true);
    }

    LeaveCriticalSection(&ctx.lock);
}

/*
 * Reapply all active hooks to all threads.
 */
void
hwbp_sync_all(void)
{
    EnterCriticalSection(&ctx.lock);

    for (int i = 0; i < 4; i++)
    {
        hook_t *hook = &ctx.hooks[i];

        if (hook->active && hook->enabled)
            apply_to_all_threads(i, hook->addr, true);
    }

    LeaveCriticalSection(&ctx.lock);
}

/*
 * Resolve a function address by module and function name.
 */
void *
hwbp_resolve(const char *mod, const char *fn)
{
    HMODULE handle = GetModuleHandleA(mod);

    if (!handle)
        handle = LoadLibraryA(mod);

    if (!handle)
        return NULL;

    return (void *)GetProcAddress(handle, fn);
}
