import json

def hex_to_int(hex_string):
    # Check if the string starts with '0x' and remove it
    if hex_string[:2].lower() == "0x":
        return int(hex_string[2:], 16)
    else:
        return int(hex_string, 16)

def to_signed_32bit(n):
    return n if n < 0x80000000 else n - 0x100000000

# Common function to handle and prettify JSON response
def pretty_print_json_response(response_data):
    try:
        json_data = json.loads(response_data)
        pretty_json = json.dumps(json_data, indent=4, sort_keys=True)
        print(pretty_json)
    except json.JSONDecodeError:
        print("Failed to decode JSON from the response.")
        
def print_ascii_art():
    color1 = f'\033[91m'
    end = f'\033[0m'
    color2 = f'\033[97m'
    color3 = f'\033[32m'
    print(f'''
                               {color2}____    __ ______  ____  ___   ____      {end} 
{color1}   _________ {end}                 {color2}/    |  /  ]      ||    |/   \\ |    \\ {end} 
{color1}  /         \\{end}                {color2}|  o  | /  /|      | |  ||     ||  _  | {end} 
{color1} / _   _   _ \\{end}               {color2}|     |/  / |_|  |_| |  ||  O  ||  |  | {end} 
{color1} |/ \\ / \\ / \\|{end}               {color2}|  _  /   \\_  |  |   |  ||     ||  |  |    {end} 
{color1}  \\  | {color3}_{end} {color1}|  /{end}                {color2}|  |  \\     | |  |   |  ||     ||  |  | {end} 
{color3}   o '(_)' o {end}                {color2}|__|__|\\____| |__|  |____|\\___/ |__|__| {end} 
{color3}    \\/.X.\\/{end}
{color3}      |_|{end}      {color2}__  ____  ___ ___ {end}     {color1} __ __   ____    __  __  _  ____  ____    ____ {end}   
{color3}     // \\\\{end}   {color2} /  ]/    ||   |   | {end}    {color1}|  |  | /    |  /  ]|  |/ ]|    ||    \\  /    |{end}   
{color3}     \\\\ //{end}   {color2}/  ] /    ||   |   |{end}     {color1}|  |  | /    |  /  ]|  |/ ]|    ||    \\  /    |{end}   
{color3}      U U{end}   {color2}/  / |  o  || _   _ | {end}    {color1}|  |  ||  o  | /  / |  ' /  |  | |  _  ||   __|{end}   
           {color2}/  /  |     ||  \\_/  | {end}    {color1}|  _  ||     |/  /  |    \\  |  | |  |  ||  |  |  {end}   
          {color2}/   \\_ |  _  ||   |   |{end}     {color1}|  |  ||  _  /   \\_ |     \\ |  | |  |  ||  |_ | {end}   
          {color2}\\     ||  |  ||   |   | {end}    {color1}|  |  ||  |  \\     ||  .  | |  | |  |  ||     | {end}   
           {color2}\\____||__|__||___|___|{end}     {color1}|__|__||__|__|\\____||__|\\_||____||__|__||___,_| {end}   

            {color3}A suite of tools for Action/Body Cameras that utilise the Viidure app 
                            (Software version: CS09-V213-20240327)\033[0m
{end}''')
