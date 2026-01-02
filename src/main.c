/*
 * main.c - hwbp usage template
 */

#include <stdio.h>
#include "hwbp.h"

/*
 * Hook callback.
 *
 * x64 calling convention:
 *   RCX, RDX, R8, R9 = args 1-4
 *   Stack at RSP+0x28 = arg 5+
 *   RAX = return value
 *
 * x86 calling convention (cdecl/stdcall):
 *   Stack at ESP+0x04 = arg 1
 *   Stack at ESP+0x08 = arg 2
 *   EAX = return value
 */
static hwbp_action_t hook_callback(PCONTEXT ctx, void *arg)
{
    (void)arg;

#if defined(_M_X64) || defined(__x86_64__)
    const char *text = (const char *)ctx->Rdx;
    const char *caption = (const char *)ctx->R8;
    printf("[HOOK] MessageBoxA called: \"%s\" - \"%s\"\n", caption, text);
#else
    const char *text = *(const char **)(ctx->Esp + 0x08);
    const char *caption = *(const char **)(ctx->Esp + 0x0C);
    printf("[HOOK] MessageBoxA called: \"%s\" - \"%s\"\n", caption, text);
#endif

    return HWBP_CONTINUE;
}

/* Data breakpoint callback - triggered on memory write. */
static hwbp_action_t write_callback(PCONTEXT ctx, void *arg)
{
    (void)ctx;
    int *watched = (int *)arg;
    printf("[WATCH] Variable modified! New value: %d\n", *watched);
    return HWBP_CONTINUE;
}

static int g_watched_var = 0;

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* Basic execute hook on MessageBoxA */
    void *target = hwbp_resolve("user32.dll", "MessageBoxA");
    int slot = hwbp_set(target, hook_callback, NULL);

    if (slot < 0) {
        printf("Failed to set hook\n");
        return 1;
    }

    printf("Hook installed in slot %d\n", slot);

    /* Data breakpoint - watch global variable for writes */
    int data_slot = hwbp_set_ex(&g_watched_var, HWBP_WRITE, HWBP_LEN_4,
                                write_callback, &g_watched_var);

    if (data_slot >= 0) {
        printf("Watching variable at %p\n", (void *)&g_watched_var);
    }

    /* Test execute hook */
    printf("\nCalling MessageBoxA...\n");
    MessageBoxA(NULL, "Hello from hooked function!", "Hook Test", MB_OK);

    /* Test data breakpoint */
    printf("\nModifying watched variable...\n");
    g_watched_var = 42;

    printf("\nModifying again...\n");
    g_watched_var = 100;

    /* Stats */
    printf("\nStatistics:\n");
    printf("  Execute hook hits: %llu\n", (unsigned long long)hwbp_hits(slot));
    printf("  Data hook hits: %llu\n", (unsigned long long)hwbp_hits(data_slot));
    printf("  Total hits: %llu\n", (unsigned long long)hwbp_total_hits());

    /* Cleanup */
    hwbp_shutdown();

    return 0;
}
