#include <stdint.h>

#define APP_PORT 4321
#define GAME_PORT 1234
#define BUFFER_SIZE 1024

#ifndef NULL
#define NULL ((void*)0)
#endif

#define KPRINTF_ADDRESS 0xc01a79a0
#define FOPEN_ADDRESS 0xc05c1dc9 // thumb
#define FCLOSE_ADDRESS 0xc05c1665 // thumb
#define FWRITE_ADDRESS 0xc05c29a1 // thumb
#define MEMSET_ADDRESS 0xc05c3cdd // thumb

#define DLOPEN_ADDRESS 0xc01ffa10
#define DLSYM_ADDRESS 0xc01ffadc

#define LWIP_SOCKET_ADDRESS 0xc01cd88c
#define LWIP_HTONL_ADDRESS 0xc01cf084
#define LWIP_HTONS_ADDRESS 0xc01cf068
#define LWIP_BIND_ADDRESS 0xc01cceb4
#define LWIP_LISTEN_ADDRESS 0xc01cd1b8
#define LWIP_ACCEPT_ADDRESS 0xc01ccc24
#define LWIP_RECV_ADDRESS 0xc01cd5d4
#define LWIP_CLOSE_ADDRESS 0xc01ccf74

#define AF_INET         2

#define INADDR_ANY      0

#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3

typedef unsigned short sa_family_t;
typedef unsigned int socklen_t;
typedef uint32_t in_addr_t;

struct sockaddr {
    uint8_t sa_len;
    uint8_t sa_family;
    char sa_data[14];
};

struct in_addr {
    uint32_t s_addr; // IP address in network byte order
};

struct sockaddr_in {
    uint8_t sin_len;
    uint8_t sin_family;
    uint16_t sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

typedef void* (*fopen_t)(const char* filename, const char* mode);
typedef int (*fclose_t)(void* stream); // Using void* instead of FILE*
typedef uint32_t (*fwrite_t)(const void* buffer, uint32_t size, uint32_t count, int32_t* stream );
typedef void (*kprintf_t)(const char* format, ...);
typedef void* (*memset_t)(void* s, int c, uint32_t n);
typedef void* (*dlopen_t)(const char* filename, int flag);
typedef void* (*dlsym_t)(void* handle, const char* symbol);

typedef int (*gameboy_main_t)();

// socket fun
int receive_and_save_file(int port, const char* file_path);
void __aeabi_memclr(void *dest, unsigned int n);

typedef int (*lwip_socket_t)(int domain, int type, int protocol);  // Equivalent of socket()
typedef uint32_t (*lwip_htonl_t)(uint32_t hostlong);  // Equivalent of htonl()
typedef uint16_t (*lwip_htons_t)(uint16_t hostshort);  // Equivalent of htons()
typedef int (*lwip_bind_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);  // Equivalent of bind()
typedef int (*lwip_listen_t)(int sockfd, int backlog);  // Equivalent of listen()
typedef int (*lwip_accept_t)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);  // Equivalent of accept()
typedef int (*lwip_recv_t)(int sockfd, void *buf, uint32_t len, int flags);
typedef int (*lwip_close_t)(int sockfd);


