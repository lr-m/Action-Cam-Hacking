SECTIONS
{
  . = SIZEOF_HEADERS;
  .text : { *(.text) }
  . = ALIGN(0x10);
  .rodata : { *(.rodata) }
  . = ALIGN(0x10);
  .data : { *(.data) }
  . = ALIGN(0x10);
  .bss : { *(.bss) }
}
