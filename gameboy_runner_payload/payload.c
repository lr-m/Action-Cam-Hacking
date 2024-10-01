#include <stdint.h>
#include "payload.h"

__attribute__((section(".text._start")))
int _start() {
    kprintf_t kprintf = (kprintf_t) KPRINTF_ADDRESS;
    memset_t memset = (memset_t) MEMSET_ADDRESS;
    dlopen_t dlopen = (dlopen_t) DLOPEN_ADDRESS;
    dlsym_t dlsym = (dlsym_t) DLSYM_ADDRESS;

    fopen_t fopen = (fopen_t) FOPEN_ADDRESS;
    fwrite_t fwrite = (fwrite_t) FWRITE_ADDRESS;
    fclose_t fclose = (fclose_t) FCLOSE_ADDRESS;

    // need to open a socket to receive the shared object
    int server_fd, new_socket;
    struct sockaddr_in addr;
    int opt = 1;
    socklen_t addrlen = sizeof(addr);
    char buffer[BUFFER_SIZE] = {0};
    int32_t *file;

    kprintf("[*] Entered payload");

    // receive the app first
    receive_and_save_file(APP_PORT, "/mnt/sdcard/gameboy.app");

    // receive the game next first
    receive_and_save_file(GAME_PORT, "/mnt/sdcard/game.gb");

    // Open the shared library
    void *handle = dlopen("/mnt/sdcard/gameboy.app", 0);
    if (!handle){
        kprintf("\n[-] dlopen failed\n\n");
        return 0;
    }

    kprintf("[*] Trying to run gameboy app\n");

    // Find the symbol for the 'main' function
    gameboy_main_t gameboy_main = (gameboy_main_t) dlsym(handle, "gameboy_main");
    if (!gameboy_main){
        kprintf("\n[-] dlsym failed\n\n");
        return 0;
    }

    // Start the gameboy app
    kprintf("[1] Starting gameboy app... Calling 0x%x\n", &gameboy_main);
    gameboy_main();

    return 0;
}

int receive_and_save_file(int port, const char* file_path) {
    lwip_socket_t lwip_socket = (lwip_socket_t) LWIP_SOCKET_ADDRESS;
    lwip_htons_t lwip_htons = (lwip_htons_t) LWIP_HTONS_ADDRESS;
    lwip_htonl_t lwip_htonl = (lwip_htonl_t) LWIP_HTONL_ADDRESS;
    lwip_bind_t lwip_bind = (lwip_bind_t) LWIP_BIND_ADDRESS;
    lwip_listen_t lwip_listen = (lwip_listen_t) LWIP_LISTEN_ADDRESS;
    lwip_accept_t lwip_accept = (lwip_accept_t) LWIP_ACCEPT_ADDRESS;
    lwip_recv_t lwip_recv = (lwip_recv_t) LWIP_RECV_ADDRESS;
    lwip_close_t lwip_close = (lwip_close_t) LWIP_CLOSE_ADDRESS;

    fopen_t fopen = (fopen_t) FOPEN_ADDRESS;
    fwrite_t fwrite = (fwrite_t) FWRITE_ADDRESS;
    fclose_t fclose = (fclose_t) FCLOSE_ADDRESS;
    kprintf_t kprintf = (kprintf_t) KPRINTF_ADDRESS;
    memset_t memset = (memset_t) MEMSET_ADDRESS;

    int server_fd, new_socket;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    char buffer[BUFFER_SIZE] = {0};
    int32_t *file;

    kprintf("[*] Beginning file receive on port %d\n", port);

    // Creating socket file descriptor using lwip_socket
    if ((server_fd = lwip_socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        kprintf("lwip_socket failed");
        return 0;
    }
    kprintf("[+] Socket create success\n");

    // Set addr to zero and initialize the struct sockaddr_in (used in LWIP)
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = lwip_htons(port);
    addr.sin_addr.s_addr = lwip_htonl(INADDR_ANY);

    // Binding the socket to port using lwip_bind
    if (lwip_bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        kprintf("lwip_bind failed");
        lwip_close(server_fd);
        return 0;
    }
    kprintf("[+] Bind success\n");

    // Listening for incoming connections using lwip_listen
    if (lwip_listen(server_fd, 3) < 0) {
        kprintf("lwip_listen failed");
        lwip_close(server_fd);
        return 0;
    }
    kprintf("[+] Listen success\n");

    // Accepting new connection using lwip_accept
    if ((new_socket = lwip_accept(server_fd, (struct sockaddr *)&addr, (socklen_t*)&addrlen)) < 0) {
        kprintf("lwip_accept failed");
        lwip_close(server_fd);
        return 0;
    }
    kprintf("[+] Accept success\n");

    file = fopen(file_path, "wb");
    if (file == NULL) {
        kprintf("Failed to open file %s", file_path);
        lwip_close(new_socket);
        lwip_close(server_fd);
        return 0;
    }
    kprintf("[+] %s open success\n", file_path);

    int32_t bytes_received;
    while ((bytes_received = lwip_recv(new_socket, buffer, BUFFER_SIZE, 0)) > 0) {
        kprintf("[*] received %d bytes\n", bytes_received);
        uint32_t written_bytes = fwrite(buffer, 1, bytes_received, file);
        if (written_bytes != bytes_received) {
            kprintf("Error writing to file\n");
            break; // or handle accordingly
        }
    }

    if (bytes_received < 0) {
        kprintf("recv failed");
        fclose(file);
        lwip_close(new_socket);
        lwip_close(server_fd);
        return 0;
    }

    kprintf("[+] File received successfully\n");

    // Cleanup
    if (fclose(file) != 0) {
        kprintf("[-] File close failed\n");
    }
    if (lwip_close(new_socket) < 0) {
        kprintf("[-] Failed to close client socket\n");
    }
    if (lwip_close(server_fd) < 0) {
        kprintf("[-] Failed to close server socket\n");
    }
    kprintf("[+] Cleanup complete!\n");

    return 1; // Success
}

void __aeabi_memclr(void *dest, unsigned int n) {
    memset_t memset = (memset_t) MEMSET_ADDRESS;
	memset(dest, 0x0, n);
}