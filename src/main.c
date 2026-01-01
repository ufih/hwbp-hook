/*
 * main.c - Entry Point
 * 
 * Template for using the hardware breakpoint hooking library.
 * Define your callback functions and install hooks below.
 */

#include <stdio.h>
#include "hwbp.h"


/*
 * Hook callback function.
 * Called when the breakpoint triggers.
 * 
 * Parameters:
 *   ctx - CPU context with full register access
 *   arg - User-provided argument
 * 
 * x64 Windows Calling Convention:
 *   ctx->Rcx            - 1st argument
 *   ctx->Rdx            - 2nd argument
 *   ctx->R8             - 3rd argument
 *   ctx->R9             - 4th argument
 *   *(ctx->Rsp + 0x28)  - 5th argument (stack)
 *   *(ctx->Rsp + 0x30)  - 6th argument (stack)
 *   ctx->Rax            - return value
 *   ctx->Rip            - instruction pointer
 * 
 * Return Values:
 *   HWBP_CONTINUE - Execute the original instruction normally
 *   HWBP_SKIP     - Skip the instruction (caller must adjust Rip)
 *   HWBP_REDIRECT - Rip was modified, jump to new location
 */
static hwbp_action_t hook(PCONTEXT ctx, void *arg)
{
    (void)ctx;
    (void)arg;

    return HWBP_CONTINUE;
}


int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* Initialize the library */
    hwbp_init();

    /*
     * Example Usage:
     * 
     * Install a hook:
     *     void *target = hwbp_resolve("user32.dll", "MessageBoxA");
     *     int slot = hwbp_set(target, hook, NULL);
     * 
     * Temporarily disable/enable:
     *     hwbp_off(slot);
     *     hwbp_on(slot);
     * 
     * Modify at runtime:
     *     hwbp_retarget(slot, new_address);
     *     hwbp_refn(slot, new_callback);
     *     hwbp_rearg(slot, new_argument);
     * 
     * Remove hooks:
     *     hwbp_del(slot);
     *     hwbp_del_addr(target);
     *     hwbp_clear();
     * 
     * Query state:
     *     int slot = hwbp_slot(target);
     *     void *addr = hwbp_addr(slot);
     *     bool enabled = hwbp_enabled(slot);
     *     int count = hwbp_count();
     * 
     * Thread synchronization:
     *     hwbp_sync(thread_id);       // Apply to specific thread
     *     hwbp_sync_all();            // Reapply to all threads
     */

    /* Cleanup */
    hwbp_shutdown();
    return 0;
}
