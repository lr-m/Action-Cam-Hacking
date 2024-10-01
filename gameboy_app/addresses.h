#include <stdint.h>

#ifndef NULL
#define NULL ((void*)0)
#endif

#define KPRINTF_ADDRESS 0xc01a79a0
#define MEMCPY_ADDRESS 0xc00084a0
#define MEMCMP_ADDRESS 0xc05c3c7d // thumb
#define SYSTEM_ADDRESS 0xc01e4094
#define USLEEP_ADDRESS 0xc0171988
#define CALLOC_ADDRESS 0xc05c1565 // thumb

#define FSEEK_ADDRESS 0xc05c2105 // thumb
#define FTELL_ADDRESS 0xc05c2471 // thumb
#define FOPEN_ADDRESS 0xc05c1dc9 // thumb
#define MALLOC_ADDRESS 0xc05c3ad5 // thumb
#define FCLOSE_ADDRESS 0xc05c1665 // thumb
#define FREAD_ADDRESS 0xc05c20b5 // thumb
#define FREE_ADDRESS 0xc05c3ae5 // thumb

// PEANUT reqs
#define QSORT_ADDRESS 0xc05c47dd // thumb
#define ABORT_ADDRESS 0xc01fd090
#define MEMSET_ADDRESS 0xc05c3cdd // thumb

// for running ELF
#define DLOPEN_ADDRESS 0xc01ffa10
#define DLSYM_ADDRESS 0xc01ffadc

typedef int (*fseek_t)( int32_t* stream, long offset, int origin );
typedef long (*ftell_t)( int32_t *stream );
typedef void* (*fopen_t)(const char* filename, const char* mode);
typedef void* (*malloc_t)(uint32_t size);
typedef int (*fclose_t)(void* stream); // Using void* instead of FILE*
typedef uint32_t (*fread_t)(void* ptr, uint32_t size, uint32_t count, void* stream); // Using void* instead of FILE*
typedef void (*free_t)(void* ptr);

typedef void (*system_t)(const char* cmd);
typedef void (*kprintf_t)(const char* format, ...);
typedef void (*usleep_t)(uint32_t useconds);
typedef void (*lb_eui_screen_standby_switch_t)();
typedef void* (*memcpy_t)(void* dest, void* src, uint32_t count);
typedef int32_t (*memcmp_t)(void* lhs, void* rhs, uint32_t count);
typedef unsigned char* (*calloc_t)(uint32_t nmemb, uint32_t size);

// for PEANUT
typedef void (*qsort_t)(void* base, uint32_t nitems, uint32_t size, int (*compar)(const void*, const void*));
typedef void (*abort_t)(void);
typedef void* (*memset_t)(void* s, int c, uint32_t n);