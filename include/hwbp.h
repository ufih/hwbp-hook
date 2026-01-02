/*
 * hwbp.h - Hardware Breakpoint Hooking Library
 *
 * Lightweight function interception using x86/x64 debug registers (DR0-DR3).
 * Supports execute, write, and read/write breakpoints with per-thread control.
 */

#ifndef HWBP_H
#define HWBP_H

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Breakpoint trigger condition. */
typedef enum {
    HWBP_EXECUTE   = 0,  /* Break on instruction execution */
    HWBP_WRITE     = 1,  /* Break on memory write */
    HWBP_IO        = 2,  /* Break on I/O port access (ring 0 only) */
    HWBP_READWRITE = 3   /* Break on memory read or write */
} hwbp_type_t;

/* Breakpoint region size. Must match address alignment. */
typedef enum {
    HWBP_LEN_1 = 0,  /* 1 byte */
    HWBP_LEN_2 = 1,  /* 2 bytes */
    HWBP_LEN_8 = 2,  /* 8 bytes (x64 only) */
    HWBP_LEN_4 = 3   /* 4 bytes */
} hwbp_len_t;

/* Callback return action. */
typedef enum {
    HWBP_CONTINUE,  /* Execute original instruction */
    HWBP_SKIP,      /* Skip instruction (callback must adjust IP) */
    HWBP_REDIRECT   /* IP was modified, continue from new address */
} hwbp_action_t;

/* Thread filter mode. */
typedef enum {
    HWBP_THREADS_ALL,      /* Apply to all threads */
    HWBP_THREADS_INCLUDE,  /* Apply only to listed threads */
    HWBP_THREADS_EXCLUDE   /* Apply to all except listed threads */
} hwbp_thread_mode_t;

/*
 * Hook callback signature.
 *
 * ctx: CPU context with full register access. Modify to alter execution.
 * arg: User data from hwbp_set().
 *
 * For data breakpoints, IP points to the faulting instruction.
 */
typedef hwbp_action_t (*hwbp_fn)(PCONTEXT ctx, void *arg);

/*
 * Lifecycle
 */

/* Initialize library. Called automatically by hwbp_set() if needed. */
bool hwbp_init(void);

/* Shutdown library. Removes all hooks and unregisters exception handler. */
void hwbp_shutdown(void);

/*
 * Hook installation
 */

/* Install execute breakpoint. Returns slot (0-3) or -1 on failure. */
int hwbp_set(void *addr, hwbp_fn fn, void *arg);

/* Install breakpoint with custom type and length. */
int hwbp_set_ex(void *addr, hwbp_type_t type, hwbp_len_t len, hwbp_fn fn, void *arg);

/*
 * Hook removal
 */

void hwbp_del(int slot);         /* Remove hook by slot */
void hwbp_del_addr(void *addr);  /* Remove hook by address */
void hwbp_clear(void);           /* Remove all hooks */

/*
 * Hook control
 */

void hwbp_on(int slot);                       /* Enable hook */
void hwbp_off(int slot);                      /* Disable hook (preserves state) */
void hwbp_retarget(int slot, void *addr);     /* Change target address */
void hwbp_refn(int slot, hwbp_fn fn);         /* Change callback */
void hwbp_rearg(int slot, void *arg);         /* Change user argument */
void hwbp_retype(int slot, hwbp_type_t type, hwbp_len_t len);  /* Change type/length */

/*
 * Per-thread filtering
 */

void hwbp_set_thread_mode(int slot, hwbp_thread_mode_t mode);
bool hwbp_thread_add(int slot, DWORD tid);   /* Returns false if list full (max 64) */
void hwbp_thread_del(int slot, DWORD tid);
void hwbp_thread_clear(int slot);

/*
 * Auto-sync
 *
 * When enabled, new threads automatically inherit active hooks.
 * Consumes one hook slot internally.
 */
bool hwbp_auto_sync(bool enable);

/*
 * Query
 */

int          hwbp_slot(void *addr);    /* Find slot by address, -1 if not found */
void        *hwbp_addr(int slot);      /* Get address for slot */
bool         hwbp_enabled(int slot);   /* Check if slot is active and enabled */
int          hwbp_count(void);         /* Count active hooks */
hwbp_type_t  hwbp_type(int slot);      /* Get breakpoint type */
hwbp_len_t   hwbp_len(int slot);       /* Get breakpoint length */

/*
 * Statistics
 */

uint64_t hwbp_hits(int slot);       /* Get hit count for slot */
void     hwbp_reset_hits(int slot); /* Reset hit counter */
uint64_t hwbp_total_hits(void);     /* Sum of all hit counts */

/*
 * Thread sync
 */

void hwbp_sync(DWORD tid);   /* Apply hooks to specific thread */
void hwbp_sync_all(void);    /* Reapply hooks to all threads */

/*
 * Utility
 */

/* Resolve function address. Loads module if not present. */
void *hwbp_resolve(const char *mod, const char *fn);

#ifdef __cplusplus
}
#endif

#endif /* HWBP_H */
