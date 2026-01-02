/*
 * hwbp.c - Hardware Breakpoint Hooking Implementation
 *
 * Uses debug registers DR0-DR3 for addresses, DR6 for status, DR7 for control.
 * Breakpoints are delivered via EXCEPTION_SINGLE_STEP to a vectored handler.
 */

#include "hwbp.h"
#include <tlhelp32.h>
#include <string.h>

#if defined(_M_X64) || defined(__x86_64__)
    #define HWBP_X64
    typedef DWORD64 reg_t;
#elif defined(_M_IX86) || defined(__i386__)
    #define HWBP_X86
    typedef DWORD reg_t;
#else
    #error "Unsupported architecture"
#endif

#define MAX_THREADS 64

typedef struct {
    void               *addr;
    hwbp_fn             fn;
    void               *arg;
    hwbp_type_t         type;
    hwbp_len_t          len;
    bool                active;
    bool                enabled;
    uint64_t            hits;
    hwbp_thread_mode_t  thread_mode;
    DWORD               threads[MAX_THREADS];
    int                 thread_count;
} slot_t;

static struct {
    slot_t            slots[4];
    PVOID             veh;
    CRITICAL_SECTION  lock;
    bool              ready;
    bool              auto_sync;
    int               auto_sync_slot;
    volatile LONG     in_handler;  /* Prevent recursion */
} g;

/*
 * DR7 bit layout per slot:
 *   Bit 2*i       : Local enable
 *   Bits 16+4*i   : Condition (2 bits) and length (2 bits)
 *
 * Condition: 00=execute, 01=write, 10=I/O, 11=read/write
 * Length:    00=1, 01=2, 10=8 (x64), 11=4
 */

static reg_t dr7_set(reg_t dr7, int slot, hwbp_type_t type, hwbp_len_t len)
{
    dr7 |= (1ULL << (slot * 2));
    dr7 &= ~(0xFULL << (16 + slot * 4));
    dr7 |= (((reg_t)type << 2) | (reg_t)len) << (16 + slot * 4);
    return dr7;
}

static reg_t dr7_clear(reg_t dr7, int slot)
{
    dr7 &= ~(1ULL << (slot * 2));
    dr7 &= ~(0xFULL << (16 + slot * 4));
    return dr7;
}

static void write_dr(PCONTEXT c, int slot, reg_t val)
{
    switch (slot) {
        case 0: c->Dr0 = val; break;
        case 1: c->Dr1 = val; break;
        case 2: c->Dr2 = val; break;
        case 3: c->Dr3 = val; break;
    }
}

static void *get_ip(PCONTEXT c)
{
#ifdef HWBP_X64
    return (void *)c->Rip;
#else
    return (void *)c->Eip;
#endif
}

static bool thread_match(slot_t *s, DWORD tid)
{
    if (s->thread_mode == HWBP_THREADS_ALL)
        return true;

    bool found = false;
    for (int i = 0; i < s->thread_count; i++) {
        if (s->threads[i] == tid) {
            found = true;
            break;
        }
    }

    return s->thread_mode == HWBP_THREADS_INCLUDE ? found : !found;
}

static void apply_thread(DWORD tid, int slot, void *addr,
                         hwbp_type_t type, hwbp_len_t len, bool enable)
{
    HANDLE h;
    bool close = false;

    if (tid == GetCurrentThreadId()) {
        h = GetCurrentThread();
    } else {
        h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                       THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!h) return;
        close = true;
        SuspendThread(h);
    }

    CONTEXT c = {0};
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(h, &c)) {
        write_dr(&c, slot, enable ? (reg_t)addr : 0);
        c.Dr7 = enable ? dr7_set(c.Dr7, slot, type, len) : dr7_clear(c.Dr7, slot);
        c.Dr6 = 0;
        SetThreadContext(h, &c);
    }

    if (close) {
        ResumeThread(h);
        CloseHandle(h);
    }
}

static void apply_all(int slot, void *addr, hwbp_type_t type, hwbp_len_t len, bool enable)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te = { .dwSize = sizeof(te) };
    DWORD pid = GetCurrentProcessId();
    slot_t *s = &g.slots[slot];

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            if (thread_match(s, te.th32ThreadID))
                apply_thread(te.th32ThreadID, slot, addr, type, len, enable);
            else
                apply_thread(te.th32ThreadID, slot, NULL, type, len, false);

        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
}

static LONG CALLBACK veh_handler(PEXCEPTION_POINTERS ex)
{
    if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    /* Prevent recursive calls from callback's memory accesses */
    if (InterlockedCompareExchange(&g.in_handler, 1, 0) != 0)
        return EXCEPTION_CONTINUE_EXECUTION;

    PCONTEXT c = ex->ContextRecord;
    EnterCriticalSection(&g.lock);

    for (int i = 0; i < 4; i++) {
        if (!(c->Dr6 & (1 << i))) continue;

        slot_t *s = &g.slots[i];
        if (!s->active || !s->enabled) continue;
        if (s->type == HWBP_EXECUTE && s->addr != get_ip(c)) continue;

        s->hits++;
        c->Dr6 &= ~(1ULL << i);

        hwbp_action_t action = s->fn ? s->fn(c, s->arg) : HWBP_CONTINUE;
        LeaveCriticalSection(&g.lock);

        if (action == HWBP_CONTINUE)
            c->EFlags |= 0x10000;  /* Resume flag */

        InterlockedExchange(&g.in_handler, 0);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    LeaveCriticalSection(&g.lock);
    InterlockedExchange(&g.in_handler, 0);
    return EXCEPTION_CONTINUE_SEARCH;
}

bool hwbp_init(void)
{
    if (g.ready) return true;

    memset(&g, 0, sizeof(g));
    InitializeCriticalSection(&g.lock);

    for (int i = 0; i < 4; i++) {
        g.slots[i].thread_mode = HWBP_THREADS_ALL;
        g.slots[i].type = HWBP_EXECUTE;
        g.slots[i].len = HWBP_LEN_1;
    }

    g.auto_sync_slot = -1;
    g.veh = AddVectoredExceptionHandler(1, veh_handler);

    if (!g.veh) {
        DeleteCriticalSection(&g.lock);
        return false;
    }

    g.ready = true;
    return true;
}

void hwbp_shutdown(void)
{
    if (!g.ready) return;

    if (g.auto_sync) hwbp_auto_sync(false);
    hwbp_clear();

    if (g.veh) RemoveVectoredExceptionHandler(g.veh);
    DeleteCriticalSection(&g.lock);
    g.ready = false;
}

int hwbp_set(void *addr, hwbp_fn fn, void *arg)
{
    return hwbp_set_ex(addr, HWBP_EXECUTE, HWBP_LEN_1, fn, arg);
}

int hwbp_set_ex(void *addr, hwbp_type_t type, hwbp_len_t len, hwbp_fn fn, void *arg)
{
    if (!g.ready && !hwbp_init()) return -1;
    if (type == HWBP_EXECUTE && len != HWBP_LEN_1) return -1;
#ifdef HWBP_X86
    if (len == HWBP_LEN_8) return -1;
#endif

    EnterCriticalSection(&g.lock);

    int slot = -1;
    for (int i = 0; i < 4; i++) {
        if (!g.slots[i].active) {
            slot = i;
            break;
        }
    }

    if (slot >= 0) {
        slot_t *s = &g.slots[slot];
        s->addr = addr;
        s->fn = fn;
        s->arg = arg;
        s->type = type;
        s->len = len;
        s->active = true;
        s->enabled = true;
        s->hits = 0;
        s->thread_mode = HWBP_THREADS_ALL;
        s->thread_count = 0;
    }

    LeaveCriticalSection(&g.lock);

    if (slot >= 0)
        apply_all(slot, addr, type, len, true);

    return slot;
}

void hwbp_del(int slot)
{
    if (slot < 0 || slot > 3 || !g.ready) return;

    EnterCriticalSection(&g.lock);

    slot_t *s = &g.slots[slot];
    if (!s->active) {
        LeaveCriticalSection(&g.lock);
        return;
    }

    hwbp_type_t type = s->type;
    hwbp_len_t len = s->len;

    s->active = false;
    s->enabled = false;
    s->hits = 0;

    LeaveCriticalSection(&g.lock);
    apply_all(slot, NULL, type, len, false);
}

void hwbp_del_addr(void *addr)
{
    int slot = hwbp_slot(addr);
    if (slot >= 0) hwbp_del(slot);
}

void hwbp_clear(void)
{
    for (int i = 0; i < 4; i++)
        hwbp_del(i);
}

void hwbp_on(int slot)
{
    if (slot < 0 || slot > 3) return;

    EnterCriticalSection(&g.lock);

    slot_t *s = &g.slots[slot];
    if (!s->active || s->enabled) {
        LeaveCriticalSection(&g.lock);
        return;
    }

    s->enabled = true;
    void *addr = s->addr;
    hwbp_type_t type = s->type;
    hwbp_len_t len = s->len;

    LeaveCriticalSection(&g.lock);
    apply_all(slot, addr, type, len, true);
}

void hwbp_off(int slot)
{
    if (slot < 0 || slot > 3) return;

    EnterCriticalSection(&g.lock);

    slot_t *s = &g.slots[slot];
    if (!s->active || !s->enabled) {
        LeaveCriticalSection(&g.lock);
        return;
    }

    s->enabled = false;
    hwbp_type_t type = s->type;
    hwbp_len_t len = s->len;

    LeaveCriticalSection(&g.lock);
    apply_all(slot, NULL, type, len, false);
}

void hwbp_retarget(int slot, void *addr)
{
    if (slot < 0 || slot > 3) return;

    EnterCriticalSection(&g.lock);

    slot_t *s = &g.slots[slot];
    if (!s->active) {
        LeaveCriticalSection(&g.lock);
        return;
    }

    s->addr = addr;
    bool enabled = s->enabled;
    hwbp_type_t type = s->type;
    hwbp_len_t len = s->len;

    LeaveCriticalSection(&g.lock);

    if (enabled)
        apply_all(slot, addr, type, len, true);
}

void hwbp_refn(int slot, hwbp_fn fn)
{
    if (slot < 0 || slot > 3) return;

    EnterCriticalSection(&g.lock);
    if (g.slots[slot].active)
        g.slots[slot].fn = fn;
    LeaveCriticalSection(&g.lock);
}

void hwbp_rearg(int slot, void *arg)
{
    if (slot < 0 || slot > 3) return;

    EnterCriticalSection(&g.lock);
    if (g.slots[slot].active)
        g.slots[slot].arg = arg;
    LeaveCriticalSection(&g.lock);
}

void hwbp_retype(int slot, hwbp_type_t type, hwbp_len_t len)
{
    if (slot < 0 || slot > 3) return;
    if (type == HWBP_EXECUTE && len != HWBP_LEN_1) return;
#ifdef HWBP_X86
    if (len == HWBP_LEN_8) return;
#endif

    EnterCriticalSection(&g.lock);

    slot_t *s = &g.slots[slot];
    if (!s->active) {
        LeaveCriticalSection(&g.lock);
        return;
    }

    s->type = type;
    s->len = len;
    bool enabled = s->enabled;
    void *addr = s->addr;

    LeaveCriticalSection(&g.lock);

    if (enabled)
        apply_all(slot, addr, type, len, true);
}

void hwbp_set_thread_mode(int slot, hwbp_thread_mode_t mode)
{
    if (slot < 0 || slot > 3) return;

    EnterCriticalSection(&g.lock);

    slot_t *s = &g.slots[slot];
    if (!s->active) {
        LeaveCriticalSection(&g.lock);
        return;
    }

    s->thread_mode = mode;
    bool enabled = s->enabled;
    void *addr = s->addr;
    hwbp_type_t type = s->type;
    hwbp_len_t len = s->len;

    LeaveCriticalSection(&g.lock);

    if (enabled)
        apply_all(slot, addr, type, len, true);
}

bool hwbp_thread_add(int slot, DWORD tid)
{
    if (slot < 0 || slot > 3) return false;

    EnterCriticalSection(&g.lock);

    slot_t *s = &g.slots[slot];
    if (!s->active || s->thread_count >= MAX_THREADS) {
        LeaveCriticalSection(&g.lock);
        return false;
    }

    for (int i = 0; i < s->thread_count; i++) {
        if (s->threads[i] == tid) {
            LeaveCriticalSection(&g.lock);
            return true;
        }
    }

    s->threads[s->thread_count++] = tid;
    bool enabled = s->enabled;
    void *addr = s->addr;
    hwbp_type_t type = s->type;
    hwbp_len_t len = s->len;

    LeaveCriticalSection(&g.lock);

    if (enabled)
        apply_all(slot, addr, type, len, true);

    return true;
}

void hwbp_thread_del(int slot, DWORD tid)
{
    if (slot < 0 || slot > 3) return;

    EnterCriticalSection(&g.lock);

    slot_t *s = &g.slots[slot];
    if (!s->active) {
        LeaveCriticalSection(&g.lock);
        return;
    }

    for (int i = 0; i < s->thread_count; i++) {
        if (s->threads[i] == tid) {
            for (int j = i; j < s->thread_count - 1; j++)
                s->threads[j] = s->threads[j + 1];
            s->thread_count--;
            break;
        }
    }

    bool enabled = s->enabled;
    void *addr = s->addr;
    hwbp_type_t type = s->type;
    hwbp_len_t len = s->len;

    LeaveCriticalSection(&g.lock);

    if (enabled)
        apply_all(slot, addr, type, len, true);
}

void hwbp_thread_clear(int slot)
{
    if (slot < 0 || slot > 3) return;

    EnterCriticalSection(&g.lock);
    if (g.slots[slot].active)
        g.slots[slot].thread_count = 0;
    LeaveCriticalSection(&g.lock);
}

static hwbp_action_t auto_sync_cb(PCONTEXT c, void *arg)
{
    (void)arg;
#ifdef HWBP_X64
    hwbp_sync((DWORD)c->Rcx);
#else
    hwbp_sync(*(DWORD *)(c->Esp + 4));
#endif
    return HWBP_CONTINUE;
}

bool hwbp_auto_sync(bool enable)
{
    if (!g.ready && !hwbp_init()) return false;
    if (enable == g.auto_sync) return true;

    if (enable) {
        void *target = hwbp_resolve("ntdll.dll", "RtlUserThreadStart");
        if (!target) return false;

        int slot = hwbp_set(target, auto_sync_cb, NULL);
        if (slot < 0) return false;

        g.auto_sync = true;
        g.auto_sync_slot = slot;
    } else {
        if (g.auto_sync_slot >= 0)
            hwbp_del(g.auto_sync_slot);
        g.auto_sync = false;
        g.auto_sync_slot = -1;
    }

    return true;
}

int hwbp_slot(void *addr)
{
    EnterCriticalSection(&g.lock);

    for (int i = 0; i < 4; i++) {
        if (g.slots[i].active && g.slots[i].addr == addr) {
            LeaveCriticalSection(&g.lock);
            return i;
        }
    }

    LeaveCriticalSection(&g.lock);
    return -1;
}

void *hwbp_addr(int slot)
{
    if (slot < 0 || slot > 3) return NULL;
    return g.slots[slot].active ? g.slots[slot].addr : NULL;
}

bool hwbp_enabled(int slot)
{
    if (slot < 0 || slot > 3) return false;
    return g.slots[slot].active && g.slots[slot].enabled;
}

int hwbp_count(void)
{
    int n = 0;
    for (int i = 0; i < 4; i++)
        if (g.slots[i].active) n++;
    return n;
}

hwbp_type_t hwbp_type(int slot)
{
    if (slot < 0 || slot > 3 || !g.slots[slot].active)
        return HWBP_EXECUTE;
    return g.slots[slot].type;
}

hwbp_len_t hwbp_len(int slot)
{
    if (slot < 0 || slot > 3 || !g.slots[slot].active)
        return HWBP_LEN_1;
    return g.slots[slot].len;
}

uint64_t hwbp_hits(int slot)
{
    if (slot < 0 || slot > 3 || !g.slots[slot].active)
        return 0;
    return g.slots[slot].hits;
}

void hwbp_reset_hits(int slot)
{
    if (slot < 0 || slot > 3) return;

    EnterCriticalSection(&g.lock);
    if (g.slots[slot].active)
        g.slots[slot].hits = 0;
    LeaveCriticalSection(&g.lock);
}

uint64_t hwbp_total_hits(void)
{
    uint64_t total = 0;

    EnterCriticalSection(&g.lock);
    for (int i = 0; i < 4; i++)
        if (g.slots[i].active)
            total += g.slots[i].hits;
    LeaveCriticalSection(&g.lock);

    return total;
}

void hwbp_sync(DWORD tid)
{
    EnterCriticalSection(&g.lock);

    for (int i = 0; i < 4; i++) {
        slot_t *s = &g.slots[i];
        if (s->active && s->enabled && thread_match(s, tid))
            apply_thread(tid, i, s->addr, s->type, s->len, true);
    }

    LeaveCriticalSection(&g.lock);
}

void hwbp_sync_all(void)
{
    EnterCriticalSection(&g.lock);

    for (int i = 0; i < 4; i++) {
        slot_t *s = &g.slots[i];
        if (s->active && s->enabled)
            apply_all(i, s->addr, s->type, s->len, true);
    }

    LeaveCriticalSection(&g.lock);
}

void *hwbp_resolve(const char *mod, const char *fn)
{
    HMODULE h = GetModuleHandleA(mod);
    if (!h) h = LoadLibraryA(mod);
    if (!h) return NULL;
    return (void *)GetProcAddress(h, fn);
}
