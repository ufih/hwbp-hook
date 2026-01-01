/*
 * hwbp.h - Hardware Breakpoint Hooking Library
 *
 * A lightweight library for intercepting function calls using CPU debug registers.
 * Supports up to 4 simultaneous hooks with full runtime control.
 * Works on both x86 (32-bit) and x64 (64-bit) Windows builds.
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
 *
 * HWBP_CONTINUE
 *   Execute the original instruction normally.
 *
 * HWBP_SKIP
 *   Skip the instruction that triggered the breakpoint.
 *   The callback is responsible for adjusting Eip/Rip to the next instruction
 *   (usually the original return address for function-level hooks).
 *
 * HWBP_REDIRECT
 *   Eip/Rip was modified in the callback and should be used as the new
 *   instruction pointer.
 */
typedef enum
{
    HWBP_CONTINUE,
    HWBP_SKIP,
    HWBP_REDIRECT

} hwbp_action_t;

/*
 * Hook callback function signature.
 *
 * Parameters:
 *   ctx - CPU context with full register access (modifiable).
 *   arg - User-provided argument passed during hook installation.
 *
 * Returns:
 *   An action indicating how execution should continue.
 *
 * Notes:
 *   - The CONTEXT structure differs between x86 and x64, but the fields used
 *     here (general-purpose registers, debug registers, Eip/Rip, Eflags)
 *     are present on both architectures.[web:141]
 *   - See README for calling convention details for each architecture.[web:127][web:129]
 */
typedef hwbp_action_t (*hwbp_fn)(PCONTEXT ctx, void *arg);

/*
 * Initialize the library.
 *
 * Registers the vectored exception handler used to receive hardware breakpoint
 * exceptions. If the library is already initialized, this function is a no-op.
 *
 * This function is called automatically by hwbp_set() if the library is not yet
 * initialized, so it is optional to call it manually.
 *
 * Returns:
 *   true  - Initialization succeeded or was already done.
 *   false - Initialization failed (e.g. could not register VEH).
 */
bool hwbp_init(void);

/*
 * Shutdown the library.
 *
 * Removes all installed hooks, clears debug registers on all threads, and
 * unregisters the vectored exception handler.
 *
 * After calling this, all previously installed hooks are inactive, and the
 * library can be reinitialized by calling hwbp_init() or hwbp_set().
 */
void hwbp_shutdown(void);

/*
 * Install a hardware breakpoint hook.
 *
 * Parameters:
 *   addr - Target address to hook. Typically a function entry point.
 *   fn   - Callback function invoked when the breakpoint triggers.
 *   arg  - User argument passed to the callback (may be NULL).
 *
 * Returns:
 *   Slot index (0–3) on success, -1 if all slots are already in use or the
 *   operation fails.
 *
 * Behavior:
 *   - Finds a free debug register slot (DR0–DR3).
 *   - Installs an execute breakpoint on 'addr' in that slot.
 *   - Applies the breakpoint to all existing threads in the current process.
 */
int hwbp_set(void *addr, hwbp_fn fn, void *arg);

/*
 * Remove a hook by slot index.
 *
 * Parameters:
 *   slot - Slot index (0–3).
 *
 * Behavior:
 *   - Marks the slot as inactive.
 *   - Clears the corresponding debug register and DR7 bits on all threads.
 */
void hwbp_del(int slot);

/*
 * Remove a hook by target address.
 *
 * Parameters:
 *   addr - Target address that was previously hooked.
 *
 * Behavior:
 *   - Finds the slot with matching address (if any).
 *   - Delegates to hwbp_del() for that slot.
 */
void hwbp_del_addr(void *addr);

/*
 * Remove all active hooks.
 *
 * Behavior:
 *   - Iterates all slots (0–3) and removes any active hooks.
 */
void hwbp_clear(void);

/*
 * Enable a previously disabled hook.
 *
 * Parameters:
 *   slot - Slot index (0–3).
 *
 * Behavior:
 *   - If the hook exists and is currently disabled, re-enables it and reapplies
 *     the breakpoint to all threads.
 */
void hwbp_on(int slot);

/*
 * Disable a hook without removing it.
 *
 * Parameters:
 *   slot - Slot index (0–3).
 *
 * Behavior:
 *   - Clears the breakpoint from all threads but keeps the metadata so it can
 *     be re-enabled with hwbp_on() later.
 */
void hwbp_off(int slot);

/*
 * Change the target address of an existing hook.
 *
 * Parameters:
 *   slot - Slot index (0–3).
 *   addr - New target address.
 *
 * Behavior:
 *   - Updates the internal address for the hook.
 *   - If the hook is enabled, re-applies the breakpoint to all threads using
 *     the new address.
 */
void hwbp_retarget(int slot, void *addr);

/*
 * Change the callback function of an existing hook.
 *
 * Parameters:
 *   slot - Slot index (0–3).
 *   fn   - New callback function.
 *
 * Behavior:
 *   - Updates the callback used when this hook triggers.
 *   - The change takes effect immediately for future hits.
 */
void hwbp_refn(int slot, hwbp_fn fn);

/*
 * Change the user argument of an existing hook.
 *
 * Parameters:
 *   slot - Slot index (0–3).
 *   arg  - New user argument pointer.
 *
 * Behavior:
 *   - Updates the user argument passed to the callback.
 */
void hwbp_rearg(int slot, void *arg);

/*
 * Find the slot index for a given address.
 *
 * Parameters:
 *   addr - Target address.
 *
 * Returns:
 *   Slot index (0–3) if found, -1 if no active hook uses this address.
 */
int hwbp_slot(void *addr);

/*
 * Get the target address for a given slot.
 *
 * Parameters:
 *   slot - Slot index (0–3).
 *
 * Returns:
 *   Address stored in the hook if active, or NULL if inactive/invalid.
 */
void *hwbp_addr(int slot);

/*
 * Check if a slot is active and enabled.
 *
 * Parameters:
 *   slot - Slot index (0–3).
 *
 * Returns:
 *   true  - Hook is active and currently enabled.
 *   false - Slot is inactive or disabled.
 */
bool hwbp_enabled(int slot);

/*
 * Get the number of active hooks.
 *
 * Returns:
 *   Number of slots that are currently active (0–4).
 */
int hwbp_count(void);

/*
 * Apply all active hooks to a specific thread.
 *
 * Parameters:
 *   tid - Target thread ID.
 *
 * Behavior:
 *   - For each active and enabled hook, sets the corresponding debug register
 *     for the specified thread only.
 *   - Useful when creating new threads that need to inherit existing hooks.
 */
void hwbp_sync(DWORD tid);

/*
 * Reapply all active hooks to all threads in the process.
 *
 * Behavior:
 *   - Enumerates all threads belonging to the current process.
 *   - For each active and enabled hook, re-applies the breakpoint for each
 *     thread.
 *   - Useful if another component modifies debug registers and you want to
 *     restore your configuration.
 */
void hwbp_sync_all(void);

/*
 * Resolve a function address by module and function name.
 *
 * Parameters:
 *   mod - Module name (e.g. "user32.dll").
 *   fn  - Function name (e.g. "MessageBoxA").
 *
 * Returns:
 *   Function address on success, NULL on failure.
 *
 * Behavior:
 *   - Calls GetModuleHandleA(mod).
 *   - If the module is not loaded, attempts LoadLibraryA(mod).
 *   - Calls GetProcAddress(handle, fn) on success.
 */
void *hwbp_resolve(const char *mod, const char *fn);

#ifdef __cplusplus
}
#endif

#endif /* HWBP_H */
