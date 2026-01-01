/*
 * hwbp.h - Hardware Breakpoint Hooking Library
 * 
 * A lightweight library for intercepting function calls using CPU debug registers.
 * Supports up to 4 simultaneous hooks with full runtime control.
 */

#ifndef HWBP_H
#define HWBP_H

#include <Windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Action to take after hook callback executes.
 */
typedef enum
{
    HWBP_CONTINUE,      /* Execute the original instruction normally */
    HWBP_SKIP,          /* Skip the instruction (caller must adjust Rip) */
    HWBP_REDIRECT       /* Rip was modified, jump to new location */

} hwbp_action_t;

/*
 * Hook callback function signature.
 * 
 * Parameters:
 *   ctx - CPU context with full register access (modifiable)
 *   arg - User-provided argument passed during hook installation
 * 
 * Returns:
 *   Action indicating how execution should continue
 */
typedef hwbp_action_t (*hwbp_fn)(PCONTEXT ctx, void *arg);

/*
 * Initialize the library.
 * Registers the Vectored Exception Handler.
 * Called automatically by hwbp_set() if not already initialized.
 * 
 * Returns:
 *   true on success, false on failure
 */
bool hwbp_init(void);

/*
 * Shutdown the library.
 * Removes all hooks, clears debug registers, and unregisters the exception handler.
 */
void hwbp_shutdown(void);

/*
 * Install a hardware breakpoint hook.
 * 
 * Parameters:
 *   addr - Target address to hook
 *   fn   - Callback function to invoke when breakpoint triggers
 *   arg  - User argument passed to callback (can be NULL)
 * 
 * Returns:
 *   Slot index (0-3) on success, -1 if all slots are occupied
 */
int hwbp_set(void *addr, hwbp_fn fn, void *arg);

/*
 * Remove a hook by slot index.
 * Clears the debug register on all threads.
 */
void hwbp_del(int slot);

/*
 * Remove a hook by target address.
 * Finds the slot and removes it.
 */
void hwbp_del_addr(void *addr);

/*
 * Remove all active hooks.
 */
void hwbp_clear(void);

/*
 * Enable a previously disabled hook.
 * Reapplies the debug register to all threads.
 */
void hwbp_on(int slot);

/*
 * Disable a hook without removing it.
 * Clears the debug register but keeps the slot occupied.
 */
void hwbp_off(int slot);

/*
 * Change the target address of an existing hook.
 * Updates the debug register on all threads if the hook is enabled.
 */
void hwbp_retarget(int slot, void *addr);

/*
 * Change the callback function of an existing hook.
 * Takes effect immediately.
 */
void hwbp_refn(int slot, hwbp_fn fn);

/*
 * Change the user argument of an existing hook.
 * Takes effect immediately.
 */
void hwbp_rearg(int slot, void *arg);

/*
 * Find the slot index for a given address.
 * 
 * Returns:
 *   Slot index (0-3) if found, -1 otherwise
 */
int hwbp_slot(void *addr);

/*
 * Get the target address of a slot.
 * 
 * Returns:
 *   Address if slot is active, NULL otherwise
 */
void *hwbp_addr(int slot);

/*
 * Check if a slot is active and enabled.
 * 
 * Returns:
 *   true if the hook is active and enabled, false otherwise
 */
bool hwbp_enabled(int slot);

/*
 * Get the number of active hooks.
 * 
 * Returns:
 *   Count of active hooks (0-4)
 */
int hwbp_count(void);

/*
 * Apply all active hooks to a specific thread.
 * Useful when a new thread is created and needs breakpoints applied.
 * 
 * Parameters:
 *   tid - Thread ID to apply hooks to
 */
void hwbp_sync(DWORD tid);

/*
 * Reapply all active hooks to all threads in the process.
 * Useful for ensuring consistency after runtime modifications.
 */
void hwbp_sync_all(void);

/*
 * Resolve a function address by module and function name.
 * Loads the module if not already loaded.
 * 
 * Parameters:
 *   mod - Module name (e.g., "user32.dll")
 *   fn  - Function name (e.g., "MessageBoxA")
 * 
 * Returns:
 *   Function address on success, NULL on failure
 */
void *hwbp_resolve(const char *mod, const char *fn);

#ifdef __cplusplus
}
#endif

#endif
