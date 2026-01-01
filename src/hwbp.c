/*
 * hwbp.c - Hardware Breakpoint Hooking Implementation
 */

#include "hwbp.h"
#include <TlHelp32.h>
#include <string.h>

/*
 * Internal hook state structure.
 */
typedef struct
{
    void    *addr;      /* Target address */
    hwbp_fn  fn;        /* Callback function */
    void    *arg;       /* User argument */
    bool     active;    /* Slot is in use */
    bool     enabled;   /* Hook is active on threads */

} hook_t;

/*
 * Global context containing all hooks and VEH state.
 */
static struct
{
    hook_t           hooks[4];      /* Four hardware breakpoint slots */
    PVOID            veh;           /* Vectored exception handler */
    CRITICAL_SECTION lock;          /* Thread safety */
    bool             ready;         /* Library initialized */

} ctx = {0};


/*
 * Enable a breakpoint in DR7.
 * Sets the local enable bit and configures for execute breakpoint (condition=00, length=00).
 */
static DWORD64 dr7_enable(DWORD64 dr7, int slot)
{
    /* Enable local breakpoint for this slot */
    dr7 |= (1ULL << (slot * 2));

    /* Clear existing condition and length bits */
    dr7 &= ~(0x0FULL << (16 + slot * 4));

    /* Condition=00 (execute), length=00 (1 byte) is already zero, so nothing to set */
    return dr7;
}


/*
 * Disable a breakpoint in DR7.
 * Clears the enable bit and condition/length fields.
 */
static DWORD64 dr7_disable(DWORD64 dr7, int slot)
{
    /* Disable local breakpoint */
    dr7 &= ~(1ULL << (slot * 2));

    /* Clear condition and length */
    dr7 &= ~(0x0FULL << (16 + slot * 4));

    return dr7;
}


/*
 * Write a value to one of the debug address registers (DR0-DR3).
 */
static void write_dr(PCONTEXT c, int slot, DWORD64 value)
{
    switch (slot)
    {
        case 0: c->Dr0 = value; break;
        case 1: c->Dr1 = value; break;
        case 2: c->Dr2 = value; break;
        case 3: c->Dr3 = value; break;
    }
}


/*
 * Apply or clear a breakpoint on a specific thread.
 * 
 * Parameters:
 *   tid    - Thread ID
 *   slot   - Debug register slot (0-3)
 *   addr   - Address to set (ignored if enable=false)
 *   enable - true to set breakpoint, false to clear
 */
static void apply_to_thread(DWORD tid, int slot, void *addr, bool enable)
{
    HANDLE thread;
    bool need_close = false;

    /* Get thread handle */
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

    /* Modify debug registers */
    CONTEXT c = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

    if (GetThreadContext(thread, &c))
    {
        write_dr(&c, slot, enable ? (DWORD64)addr : 0);
        c.Dr7 = enable ? dr7_enable(c.Dr7, slot) : dr7_disable(c.Dr7, slot);
        c.Dr6 = 0;  /* Clear status register */
        SetThreadContext(thread, &c);
    }

    /* Cleanup */
    if (need_close)
    {
        ResumeThread(thread);
        CloseHandle(thread);
    }
}


/*
 * Apply or clear a breakpoint on all threads in the process.
 * Enumerates threads via toolhelp snapshot.
 */
static void apply_to_all_threads(int slot, void *addr, bool enable)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 entry = { .dwSize = sizeof(entry) };
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
 * Catches EXCEPTION_SINGLE_STEP, identifies which breakpoint triggered,
 * and invokes the corresponding callback.
 */
static LONG CALLBACK exception_handler(PEXCEPTION_POINTERS info)
{
    /* Only handle single-step exceptions */
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT c = info->ContextRecord;

    EnterCriticalSection(&ctx.lock);

    /* Check each debug register */
    for (int i = 0; i < 4; i++)
    {
        /* Check if this breakpoint triggered (DR6 status bit) */
        if (!(c->Dr6 & (1 << i)))
            continue;

        hook_t *hook = &ctx.hooks[i];

        /* Verify hook is active and enabled */
        if (!hook->active || !hook->enabled)
            continue;

        /* Verify RIP matches the hook address */
        if (hook->addr != (void *)c->Rip)
            continue;

        /* Clear the status bit */
        c->Dr6 &= ~(1ULL << i);

        /* Invoke user callback */
        hwbp_action_t action = HWBP_CONTINUE;

        if (hook->fn)
            action = hook->fn(c, hook->arg);

        LeaveCriticalSection(&ctx.lock);

        /*
         * Set Resume Flag (RF) in EFLAGS to skip the breakpoint for one instruction.
         * This prevents infinite loop when continuing execution.
         */
        if (action == HWBP_CONTINUE)
            c->EFlags |= 0x10000;

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    LeaveCriticalSection(&ctx.lock);
    return EXCEPTION_CONTINUE_SEARCH;
}


bool hwbp_init(void)
{
    if (ctx.ready)
        return true;

    memset(&ctx, 0, sizeof(ctx));
    InitializeCriticalSection(&ctx.lock);

    /* Register our exception handler (first in chain) */
    ctx.veh = AddVectoredExceptionHandler(1, exception_handler);

    if (!ctx.veh)
    {
        DeleteCriticalSection(&ctx.lock);
        return false;
    }

    ctx.ready = true;
    return true;
}


void hwbp_shutdown(void)
{
    if (!ctx.ready)
        return;

    /* Remove all hooks */
    hwbp_clear();

    /* Unregister exception handler */
    if (ctx.veh)
        RemoveVectoredExceptionHandler(ctx.veh);

    DeleteCriticalSection(&ctx.lock);
    ctx.ready = false;
}


int hwbp_set(void *addr, hwbp_fn fn, void *arg)
{
    if (!ctx.ready && !hwbp_init())
        return -1;

    EnterCriticalSection(&ctx.lock);

    /* Find a free slot */
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

    /* Apply to all threads */
    if (slot >= 0)
        apply_to_all_threads(slot, addr, true);

    return slot;
}


void hwbp_del(int slot)
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

    /* Clear from all threads */
    apply_to_all_threads(slot, NULL, false);
}


void hwbp_del_addr(void *addr)
{
    int slot = hwbp_slot(addr);

    if (slot >= 0)
        hwbp_del(slot);
}


void hwbp_clear(void)
{
    for (int i = 0; i < 4; i++)
        hwbp_del(i);
}


void hwbp_on(int slot)
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


void hwbp_off(int slot)
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


void hwbp_retarget(int slot, void *addr)
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

    /* Reapply if currently enabled */
    if (enabled)
        apply_to_all_threads(slot, addr, true);
}


void hwbp_refn(int slot, hwbp_fn fn)
{
    if (slot < 0 || slot > 3)
        return;

    EnterCriticalSection(&ctx.lock);

    if (ctx.hooks[slot].active)
        ctx.hooks[slot].fn = fn;

    LeaveCriticalSection(&ctx.lock);
}


void hwbp_rearg(int slot, void *arg)
{
    if (slot < 0 || slot > 3)
        return;

    EnterCriticalSection(&ctx.lock);

    if (ctx.hooks[slot].active)
        ctx.hooks[slot].arg = arg;

    LeaveCriticalSection(&ctx.lock);
}


int hwbp_slot(void *addr)
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


void *hwbp_addr(int slot)
{
    if (slot < 0 || slot > 3)
        return NULL;

    return ctx.hooks[slot].active ? ctx.hooks[slot].addr : NULL;
}


bool hwbp_enabled(int slot)
{
    if (slot < 0 || slot > 3)
        return false;

    return ctx.hooks[slot].active && ctx.hooks[slot].enabled;
}


int hwbp_count(void)
{
    int count = 0;

    for (int i = 0; i < 4; i++)
    {
        if (ctx.hooks[i].active)
            count++;
    }

    return count;
}


void hwbp_sync(DWORD tid)
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


void hwbp_sync_all(void)
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


void *hwbp_resolve(const char *mod, const char *fn)
{
    HMODULE handle = GetModuleHandleA(mod);

    if (!handle)
        handle = LoadLibraryA(mod);

    if (!handle)
        return NULL;

    return (void *)GetProcAddress(handle, fn);
}
