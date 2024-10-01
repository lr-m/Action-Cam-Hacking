ENTRY(_start)
SECTIONS {
    . = 0x0;
    .text : {
        *(.text._start)        /* Place _start first */
        *(.text*)              /* All remaining .text sections */
    }
    .rodata : {
        *(.rodata*)            /* All .rodata sections */
    }
}