#define __DEBUG__ 1             // General debugging statements
#define __DEBUG_HOOK__ 1        // Debugging of inline function hooking

//extern unsigned long *sys_call_table;

char *strnstr ( const char *haystack, const char *needle, size_t n );
void *memmem ( const void *haystack, size_t haystack_size, const void *needle, size_t needle_size );
void *memstr ( const void *haystack, const char *needle, size_t size );

void hijack_start ( void *target, void *new );
void hijack_pause ( void *target );
void hijack_resume ( void *target );
void hijack_stop ( void *target );

#if defined(_CONFIG_X86_64_)
extern unsigned long *ia32_sys_call_table;
#endif
