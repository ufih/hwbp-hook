/*
 * main.c - Entry Point
 *
 * Template for using the hardware breakpoint hooking library.
 * Define your callback functions and install hooks in main().
 */

#include <stdio.h>
#include "hwbp.h"

/*
 * Hook callback function.
 * Called when the breakpoint triggers.
 *
 * Parameters:
 *   ctx - CPU context with full register access.
 *   arg - User-provided argument from hwbp_set().
 *
 * Windows x64 calling convention (Microsoft):
 *   - 1st argument: RCX  (ctx->Rcx)
 *   - 2nd argument: RDX  (ctx->Rdx)
 *   - 3rd argument: R8   (ctx->R8)
 *   - 4th argument: R9   (ctx->R9)
 *   - Further arguments are on the stack at ctx->Rsp + 0x28, ...
 *   - Return value is in Rax (ctx->Rax).[web:127][web:141]
 *
 * Windows x86 calling convention (cdecl/stdcall):
 *   - Return address at *(DWORD *)ctx->Esp
 *   - 1st argument at *(DWORD *)(ctx->Esp + 0x04)
 *   - 2nd argument at *(DWORD *)(ctx->Esp + 0x08)
 *   - 3rd argument at *(DWORD *)(ctx->Esp + 0x0C)
 *   - Return value is in Eax (ctx->Eax).[web:129][web:134]
 *
 * Return values:
 *   HWBP_CONTINUE - Execute the original instruction normally.
 *   HWBP_SKIP     - Skip the current instruction (you must adjust Eip/Rip).
 *   HWBP_REDIRECT - Eip/Rip was modified, execution will continue from there.
 */
static hwbp_action_t
hook(PCONTEXT ctx, void *arg)
{
    (void)ctx;
    (void)arg;

    /*
     * Examples (x64):
     *   - Inspect arguments:
     *       void *arg1 = (void *)ctx->Rcx;
     *       void *arg2 = (void *)ctx->Rdx;
     *
     *   - Modify arguments:
     *       ctx->Rcx = (DWORD64)new_value;
     *
     *   - Redirect execution:
     *       ctx->Rip = (DWORD64)other_function;
     *       return HWBP_REDIRECT;
     *
     *   - Block call and fake return:
     *       ctx->Rax = fake_return_value;
     *       ctx->Rip = *(DWORD64 *)ctx->Rsp;  // pop return address
     *       ctx->Rsp += 8;
     *       return HWBP_SKIP;
     *
     * Examples (x86):
     *   - Inspect first stack argument:
     *       DWORD arg1 = *(DWORD *)(ctx->Esp + 0x04);
     *
     *   - Fake return:
     *       ctx->Eax = fake_return_value;
     *       ctx->Eip = *(DWORD *)ctx->Esp;    // pop return address
     *       ctx->Esp += 4;
     *       return HWBP_SKIP;
     */

    return HWBP_CONTINUE;
}

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* Initialize the library (optional, hwbp_set() will auto-init). */
    hwbp_init();

    /*
     * Example usage:
     *
     * Install a hook:
     *
     *     void *target = hwbp_resolve("user32.dll", "MessageBoxA");
     *     int slot      = hwbp_set(target, hook, NULL);
     *
     * Temporarily disable/enable:
     *
     *     hwbp_off(slot);
     *     hwbp_on(slot);
     *
     * Modify at runtime:
     *
     *     hwbp_retarget(slot, new_address);
     *     hwbp_refn(slot, new_callback);
     *     hwbp_rearg(slot, new_argument);
     *
     * Remove hooks:
     *
     *     hwbp_del(slot);
     *     hwbp_del_addr(target);
     *     hwbp_clear();
     *
     * Query state:
     *
     *     int  s       = hwbp_slot(target);
     *     void *addr   = hwbp_addr(s);
     *     bool enabled = hwbp_enabled(s);
     *     int  count   = hwbp_count();
     *
     * Thread synchronization (for new threads):
     *
     *     hwbp_sync(thread_id);   // Apply to specific thread
     *     hwbp_sync_all();        // Reapply to all threads
     */

    /* Cleanup before exit. */
    hwbp_shutdown();

    return 0;
}
