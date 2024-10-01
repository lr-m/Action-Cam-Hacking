#include "gameboy_app.h"
#include "buttons.h"
#include "rom.h"
#include "lcd.h"
#include "mem.h"
#include "cpu.h"
#include "timer.h"

int gameboy_main() {
    kprintf_t kprintf = (kprintf_t) KPRINTF_ADDRESS;
    kprintf("[2] Hello from dynamically loaded gameboy_main function!\n");

    // if display is off turn it on
    char * display_on_ptr = (char*) 0xc09d7bb0;
    char display_on = *display_on_ptr;
    kprintf("[*] Display on status: %d\n", display_on);
    if (!display_on){
        lb_eui_screen_standby_switch_t lb_eui_screen_standby_switch = (lb_eui_screen_standby_switch_t) 0xc00839f4;
        lb_eui_screen_standby_switch();
    }

    // hijack button handler with our handler
    uint32_t* key_obj_ptr = (uint32_t*) 0xc09d7b60;
    void (**key_callback_ptr)(int, int*) = (void (**)(int, int*)) ((uintptr_t)*key_obj_ptr + 0xc);
    *key_callback_ptr = button_press_handle;

    int r = rom_load("/mnt/sdcard/game.gb");

    kprintf("[+] ROM load OK\n");

    // Pointer to framebuffer
    uint32_t* framebuffer_thing_ptr = (uint32_t*) 0xc0aabb9c;
    uint32_t* framebuffer_obj_ptr_1 = (uint32_t*) ((*framebuffer_thing_ptr) + 0xc);
    uint32_t* framebuffer_obj_ptr_2 = (uint32_t*) ((*framebuffer_thing_ptr) + 0x2c);
    uint32_t* framebuffer_ptr_1 = (uint32_t*) *framebuffer_obj_ptr_1;
    uint32_t* framebuffer_ptr_2 = (uint32_t*) *framebuffer_obj_ptr_2;

    // Print the pointers using kprintf
    kprintf("Pointer to ptr: 0x%08x\n", (unsigned int)framebuffer_thing_ptr);
    kprintf("Pointer to framebuffer obj ptr_1: 0x%08x\n", (unsigned int)framebuffer_obj_ptr_1);
    kprintf("Pointer to framebuffer obj ptr_2: 0x%08x\n", (unsigned int)framebuffer_obj_ptr_2);
    kprintf("Pointer to framebuffer 1: 0x%08x\n", (unsigned int)framebuffer_ptr_1);
    kprintf("Pointer to framebuffer 2: 0x%08x\n", (unsigned int)framebuffer_ptr_2);

    lcd_init(framebuffer_ptr_1, framebuffer_ptr_2);  
    kprintf("[+] LCD init\n");

    mem_init();
    kprintf("[+] MEM init\n");

    cpu_init();
    kprintf("[+] CPU init\n");

    r = 0;

    while (1) {
        if (!cpu_cycle()) break;

        int cycles_to_catch_up = cpu_get_cycles() - r;
        
        if (cycles_to_catch_up > 0) { 
            do {
                for (int i = 0; i < 4; i++) {
                    if (!lcd_cycle()) goto out;
                }
                r++;
            } while (--cycles_to_catch_up > 0);

            timer_cycle();
        }
    }

out:

    return 0;
}

