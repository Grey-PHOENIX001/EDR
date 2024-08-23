# import subprocess
# import signal
# import sys
# import os
# from datetime import datetime
# from mitmproxy import ctx, http


# blocked_domains = []
# blocked_paths = []
# # File name
# file_name = "Blocked_host"

# # Check if file exists
# if os.path.exists(file_name):
#     # If the file exists, read the domains and paths
#     with open(file_name, "r") as file:
#         blocked_data = file.read().splitlines()
#         blocked_domains = [line for line in blocked_data if not line.startswith('/')]
#         blocked_paths = [line for line in blocked_data if line.startswith('/')]
        
#         print("Blocked domains:")
#         for domain in blocked_domains:
#             print(domain)
        
#         print("\nBlocked paths:")
#         for path in blocked_paths:
#             print(path)
# else:
#     # If the file does not exist, create it with a prompt
#     with open(file_name, "w") as file:
#         file.write("# Enter your blocked domains and paths here.\n")
#         file.write("# Example:\n")
#         file.write("example.com\n")
#         file.write("/example_path\n")
#     print(f"File '{file_name}' created. Please enter your blocked domains and paths in the file.")

# proxy_enabled = False  

# class Logger:
#     def __init__(self):
#         self.log_file = open("network_log.txt", "a")

#     def log_request(self, flow: http.HTTPFlow) -> None:
#         source_ip, source_port = flow.client_conn.address
#         dest_ip, dest_port = flow.server_conn.address
        
#         log_message = f"======= Request =======\n"
#         log_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
#         log_message += f"URL: {flow.request.pretty_url}\n"
#         log_message += f"Method: {flow.request.method}\n"
#         log_message += f"Host: {flow.request.host}\n"
#         log_message += f"Source IP: {source_ip}:{source_port}\n"
#         log_message += f"Destination IP: {dest_ip}:{dest_port}\n"
#         log_message += f"Port: {flow.request.port}\n"
#         log_message += f"Protocol: HTTP\n" 
#         log_message += f"Event ID: REQUEST\n"
#         log_message += f"Severity Level: Info\n"
#         log_message += "=======================\n\n"
        
#         print(log_message.strip())
#         self.log_file.write(log_message)

#     def log_response(self, flow: http.HTTPFlow) -> None:
#         source_ip, source_port = flow.client_conn.address
#         dest_ip, dest_port = flow.server_conn.address
        
#         log_message = f"======= Response =======\n"
#         log_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
#         log_message += f"URL: {flow.request.pretty_url}\n"
#         log_message += f"Method: {flow.request.method}\n"
#         log_message += f"Host: {flow.request.host}\n"
#         log_message += f"Source IP: {source_ip}:{source_port}\n"
#         log_message += f"Destination IP: {dest_ip}:{dest_port}\n"
#         log_message += f"Port: {flow.request.port}\n"
#         log_message += f"Protocol: HTTP\n"
#         log_message += f"Event ID: RESPONSE\n"
#         log_message += f"Severity Level: Info\n"
#         log_message += "=======================\n\n"
        
#         print(log_message.strip())
#         self.log_file.write(log_message)

#     def done(self):
#         self.log_file.close()

# logger = Logger()

# def enable_proxy():
#     global proxy_enabled
#     try:
#         command_proxy = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "http=127.0.0.1:8080;https=127.0.0.1:8080;ftp=127.0.0.1:8080" /f'
#         subprocess.run(command_proxy, shell=True, check=True)

#         command_enable = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f'
#         subprocess.run(command_enable, shell=True, check=True)

#         proxy_enabled = True
#     except subprocess.CalledProcessError as e:
#         print(f"Failed to enable proxy: {e}")
#         sys.exit(1)

# def registry_value_exists(key, value):
#     command_check = f'reg query "{key}" /v {value}'
#     result = subprocess.run(command_check, shell=True, capture_output=True)
#     return result.returncode == 0

# def disable_proxy():
#     global proxy_enabled
#     try:
#         proxy_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#         if registry_value_exists(proxy_key, "ProxyServer"):
#             command_disable_proxy = f'reg delete "{proxy_key}" /v ProxyServer /f'
#             subprocess.run(command_disable_proxy, shell=True, check=True)

#         if registry_value_exists(proxy_key, "ProxyEnable"):
#             command_disable_enable = f'reg delete "{proxy_key}" /v ProxyEnable /f'
#             subprocess.run(command_disable_enable, shell=True, check=True)

#         proxy_enabled = False
#     except subprocess.CalledProcessError as e:
#         print(f"Failed to disable proxy: {e}")
#         sys.exit(1)

# def start_mitmproxy():
#     try:
#         enable_proxy()

#         command = [
#             "mitmdump",
#             "--set", "connection_strategy=eager",
#             "--set", "stream_large_bodies=1500b",
#             "--set", "console_eventlog_verbosity=error",
#             "--set", "ssl_insecure=true",
#             "-s", __file__
#         ]
#         mitmdump_process = subprocess.Popen(command)

#         try:
#             mitmdump_process.wait()
#         except KeyboardInterrupt:
#             print("\nCtrl+C detected. Stopping and disabling the server...")
#             sys.exit(0)
#         finally:
#             disable_proxy()
#     except Exception as e:
#         print(f"Error starting mitmdump: {e}")
#         disable_proxy()
#         sys.exit(1)

# def request(flow: http.HTTPFlow) -> None:
#     global blocked_domains, blocked_paths
    
#     if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://"):
#         logger.log_request(flow)

#         if any(domain in flow.request.host for domain in blocked_domains) or any(path in flow.request.path for path in blocked_paths):
#             with open("web_warning.html", "r", encoding="utf-8") as f:
#                 html_content = f.read()
#             flow.response = http.Response.make(
#                 403,  
#                 html_content,  
#                 {"Content-Type": "text/html"} 
#             )
#             print(f"Blocked a request to {flow.request.pretty_url}")

# def response(flow: http.HTTPFlow) -> None:
#     global blocked_domains, blocked_paths
    
#     if flow.response:
#         logger.log_response(flow)

# def main():
#     signal.signal(signal.SIGINT, lambda sig, frame: (disable_proxy(), sys.exit(0)))
#     print("Starting Server...")
#     start_mitmproxy()

# if __name__ == "__main__":
#     main()

# import subprocess
# import signal
# import sys
# import os
# from datetime import datetime
# from mitmproxy import ctx, http

# file_name = "Blocked_host"

# # Global variables for blocked domains and paths
# blocked_domains = []
# blocked_paths = []

# # Check if file exists and read blocked domains/paths
# if os.path.exists(file_name):
#     with open(file_name, "r") as file:
#         blocked_data = file.read().splitlines()
#         blocked_domains = [line for line in blocked_data if not line.startswith('/')]
#         blocked_paths = [line for line in blocked_data if line.startswith('/')]
# else:
#     with open(file_name, "w") as file:
#         file.write("# Enter your blocked domains and paths here.\n")
#         file.write("# Example:\n")
#         file.write("example.com\n")
#         file.write("/example_path\n")
#     print(f"File '{file_name}' created. Please enter your blocked domains and paths in the file.")
#     sys.exit(0)  # Exit since there's nothing to block

# proxy_enabled = False

# class Logger:
#     def __init__(self):
#         self.log_file = open("network_log.txt", "a")

#     def log_request(self, flow: http.HTTPFlow) -> None:
#         source_ip, source_port = flow.client_conn.address
#         dest_ip, dest_port = flow.server_conn.address
        
#         log_message = f"======= Request =======\n"
#         log_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
#         log_message += f"URL: {flow.request.pretty_url}\n"
#         log_message += f"Method: {flow.request.method}\n"
#         log_message += f"Host: {flow.request.host}\n"
#         log_message += f"Source IP: {source_ip}:{source_port}\n"
#         log_message += f"Destination IP: {dest_ip}:{dest_port}\n"
#         log_message += f"Port: {flow.request.port}\n"
#         log_message += f"Protocol: HTTP\n"
#         log_message += f"Event ID: REQUEST\n"
#         log_message += f"Severity Level: Info\n"
#         log_message += "=======================\n\n"
        
#         print(log_message.strip())
#         self.log_file.write(log_message)

#     def log_response(self, flow: http.HTTPFlow) -> None:
#         source_ip, source_port = flow.client_conn.address
#         dest_ip, dest_port = flow.server_conn.address
        
#         log_message = f"======= Response =======\n"
#         log_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
#         log_message += f"URL: {flow.request.pretty_url}\n"
#         log_message += f"Method: {flow.request.method}\n"
#         log_message += f"Host: {flow.request.host}\n"
#         log_message += f"Source IP: {source_ip}:{source_port}\n"
#         log_message += f"Destination IP: {dest_ip}:{dest_port}\n"
#         log_message += f"Port: {flow.request.port}\n"
#         log_message += f"Protocol: HTTP\n"
#         log_message += f"Event ID: RESPONSE\n"
#         log_message += f"Severity Level: Info\n"
#         log_message += "=======================\n\n"
        
#         print(log_message.strip())
#         self.log_file.write(log_message)

#     def done(self):
#         self.log_file.close()

# logger = Logger()

# def enable_proxy():
#     global proxy_enabled
#     try:
#         command_proxy = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "http=127.0.0.1:8080;https=127.0.0.1:8080;ftp=127.0.0.1:8080" /f'
#         subprocess.run(command_proxy, shell=True, check=True)

#         command_enable = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f'
#         subprocess.run(command_enable, shell=True, check=True)

#         proxy_enabled = True
#     except subprocess.CalledProcessError as e:
#         print(f"Failed to enable proxy: {e}")
#         sys.exit(1)

# def registry_value_exists(key, value):
#     command_check = f'reg query "{key}" /v {value}'
#     result = subprocess.run(command_check, shell=True, capture_output=True)
#     return result.returncode == 0

# def disable_proxy():
#     global proxy_enabled
#     try:
#         proxy_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#         if registry_value_exists(proxy_key, "ProxyServer"):
#             command_disable_proxy = f'reg delete "{proxy_key}" /v ProxyServer /f'
#             subprocess.run(command_disable_proxy, shell=True, check=True)

#         if registry_value_exists(proxy_key, "ProxyEnable"):
#             command_disable_enable = f'reg delete "{proxy_key}" /v ProxyEnable /f'
#             subprocess.run(command_disable_enable, shell=True, check=True)

#         proxy_enabled = False
#     except subprocess.CalledProcessError as e:
#         print(f"Failed to disable proxy: {e}")
#         sys.exit(1)

# def start_mitmproxy():
#     try:
#         enable_proxy()

#         command = [
#             "mitmdump",
#             "--set", "connection_strategy=eager",
#             "--set", "stream_large_bodies=1500b",
#             "--set", "console_eventlog_verbosity=error",
#             "--set", "ssl_insecure=true",
#             "-s", __file__
#         ]
#         mitmdump_process = subprocess.Popen(command)

#         try:
#             mitmdump_process.wait()
#         except KeyboardInterrupt:
#             print("\nCtrl+C detected. Stopping and disabling the server...")
#             sys.exit(0)
#         finally:
#             disable_proxy()
#     except Exception as e:
#         print(f"Error starting mitmdump: {e}")
#         disable_proxy()
#         sys.exit(1)

# def request(flow: http.HTTPFlow) -> None:
#     global blocked_domains, blocked_paths
    
#     if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://"):
#         logger.log_request(flow)

#         if any(domain in flow.request.host for domain in blocked_domains) or any(path in flow.request.path for path in blocked_paths):
#             with open("web_warning.html", "r", encoding="utf-8") as f:
#                 html_content = f.read()
#             flow.response = http.Response.make(
#                 403,  
#                 html_content,  
#                 {"Content-Type": "text/html"} 
#             )
#             print(f"Blocked a request to {flow.request.pretty_url}")

# def response(flow: http.HTTPFlow) -> None:
#     global blocked_domains, blocked_paths
    
#     if flow.response:
#         logger.log_response(flow)

# def main():
#     signal.signal(signal.SIGINT, lambda sig, frame: (disable_proxy(), sys.exit(0)))
#     print("Starting Server...")
#     start_mitmproxy()

# if __name__ == "__main__":
#     main()

# import subprocess
# import signal
# import sys
# import os
# from datetime import datetime
# from mitmproxy import ctx, http

# # File name
# file_name = "Blocked_host"

# def load_blocked_data():
#     """Load blocked domains and paths from the file."""
#     if os.path.exists(file_name):
#         with open(file_name, "r") as file:
#             blocked_data = file.read().splitlines()
#             blocked_domains = [line for line in blocked_data if not line.startswith('/')]
#             blocked_paths = [line for line in blocked_data if line.startswith('/')]
#             return blocked_domains, blocked_paths
#     else:
#         with open(file_name, "w") as file:
#             file.write("# Enter your blocked domains and paths here.\n")
#             file.write("# Example:\n")
#             file.write("example.com\n")
#             file.write("/example_path\n")
#         print(f"File '{file_name}' created. Please enter your blocked domains and paths in the file.")
#         sys.exit(0)  # Exit since there's nothing to block
#     return [], []

# proxy_enabled = False

# class Logger:
#     def __init__(self):
#         self.log_file = open("network_log.txt", "a")

#     def log_request(self, flow: http.HTTPFlow) -> None:
#         source_ip, source_port = flow.client_conn.address
#         dest_ip, dest_port = flow.server_conn.address
        
#         log_message = f"======= Request =======\n"
#         log_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
#         log_message += f"URL: {flow.request.pretty_url}\n"
#         log_message += f"Method: {flow.request.method}\n"
#         log_message += f"Host: {flow.request.host}\n"
#         log_message += f"Source IP: {source_ip}:{source_port}\n"
#         log_message += f"Destination IP: {dest_ip}:{dest_port}\n"
#         log_message += f"Port: {flow.request.port}\n"
#         log_message += f"Protocol: HTTP\n"
#         log_message += f"Event ID: REQUEST\n"
#         log_message += f"Severity Level: Info\n"
#         log_message += "=======================\n\n"
        
#         print(log_message.strip())
#         self.log_file.write(log_message)

#     def log_response(self, flow: http.HTTPFlow) -> None:
#         source_ip, source_port = flow.client_conn.address
#         dest_ip, dest_port = flow.server_conn.address
        
#         log_message = f"======= Response =======\n"
#         log_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
#         log_message += f"URL: {flow.request.pretty_url}\n"
#         log_message += f"Method: {flow.request.method}\n"
#         log_message += f"Host: {flow.request.host}\n"
#         log_message += f"Source IP: {source_ip}:{source_port}\n"
#         log_message += f"Destination IP: {dest_ip}:{dest_port}\n"
#         log_message += f"Port: {flow.request.port}\n"
#         log_message += f"Protocol: HTTP\n"
#         log_message += f"Event ID: RESPONSE\n"
#         log_message += f"Severity Level: Info\n"
#         log_message += "=======================\n\n"
        
#         print(log_message.strip())
#         self.log_file.write(log_message)

#     def done(self):
#         self.log_file.close()

# logger = Logger()

# def enable_proxy():
#     global proxy_enabled
#     try:
#         command_proxy = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "http=127.0.0.1:8080;https=127.0.0.1:8080;ftp=127.0.0.1:8080" /f'
#         subprocess.run(command_proxy, shell=True, check=True)

#         command_enable = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f'
#         subprocess.run(command_enable, shell=True, check=True)

#         proxy_enabled = True
#     except subprocess.CalledProcessError as e:
#         print(f"Failed to enable proxy: {e}")
#         sys.exit(1)

# def registry_value_exists(key, value):
#     command_check = f'reg query "{key}" /v {value}'
#     result = subprocess.run(command_check, shell=True, capture_output=True)
#     return result.returncode == 0

# def disable_proxy():
#     global proxy_enabled
#     try:
#         proxy_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#         if registry_value_exists(proxy_key, "ProxyServer"):
#             command_disable_proxy = f'reg delete "{proxy_key}" /v ProxyServer /f'
#             subprocess.run(command_disable_proxy, shell=True, check=True)

#         if registry_value_exists(proxy_key, "ProxyEnable"):
#             command_disable_enable = f'reg delete "{proxy_key}" /v ProxyEnable /f'
#             subprocess.run(command_disable_enable, shell=True, check=True)

#         proxy_enabled = False
#     except subprocess.CalledProcessError as e:
#         print(f"Failed to disable proxy: {e}")
#         sys.exit(1)

# def start_mitmproxy():
#     try:
#         enable_proxy()

#         command = [
#             "mitmdump",
#             "--set", "connection_strategy=eager",
#             "--set", "stream_large_bodies=1500b",
#             "--set", "console_eventlog_verbosity=error",
#             "--set", "ssl_insecure=true",
#             "-s", __file__
#         ]
#         mitmdump_process = subprocess.Popen(command)

#         try:
#             mitmdump_process.wait()
#         except KeyboardInterrupt:
#             print("\nCtrl+C detected. Stopping and disabling the server...")
#             sys.exit(0)
#         finally:
#             disable_proxy()
#     except Exception as e:
#         print(f"Error starting mitmdump: {e}")
#         disable_proxy()
#         sys.exit(1)

# def request(flow: http.HTTPFlow) -> None:
#     # Load the latest blocked domains and paths
#     blocked_domains, blocked_paths = load_blocked_data()
    
#     if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://"):
#         logger.log_request(flow)

#         if any(domain in flow.request.host for domain in blocked_domains) or any(path in flow.request.path for path in blocked_paths):
#             with open("web_warning.html", "r", encoding="utf-8") as f:
#                 html_content = f.read()
#             flow.response = http.Response.make(
#                 403,  
#                 html_content,  
#                 {"Content-Type": "text/html"} 
#             )
#             print(f"Blocked a request to {flow.request.pretty_url}")

# def response(flow: http.HTTPFlow) -> None:
#     # Log response details
#     if flow.response:
#         logger.log_response(flow)

# def main():
#     signal.signal(signal.SIGINT, lambda sig, frame: (disable_proxy(), sys.exit(0)))
#     print("Starting Server...")
#     start_mitmproxy()

# if __name__ == "__main__":
#     main()

import subprocess
import signal
import sys
import os
from datetime import datetime
from mitmproxy import ctx, http

# File name for blocked domains and paths
file_name = "Blocked_host"

# Path to your custom HTML file for blocked sites
custom_html_path = "web_warning.html"

# Initialize empty lists for blocked domains and paths
blocked_domains = []
blocked_paths = []

def load_blocked_data():
    """Load blocked domains and paths from the file."""
    global blocked_domains, blocked_paths  # Ensure the function modifies the global variables

    blocked_domains = []  # Clear the previous blocked domains
    blocked_paths = []    # Clear the previous blocked paths

    if os.path.exists(file_name):
        with open(file_name, "r") as file:
            blocked_data = file.read().splitlines()
            blocked_domains = [line.strip() for line in blocked_data if not line.startswith('/') and line.strip()]
            blocked_paths = [line.strip() for line in blocked_data if line.startswith('/') and line.strip()]
    else:
        with open(file_name, "w") as file:
            file.write("# Enter your blocked domains and paths here.\n")
            file.write("# Example:\n")
            file.write("example.com\n")
            file.write("/example_path\n")
        print(f"File '{file_name}' created. Please enter your blocked domains and paths in the file.")
        sys.exit(0)  # Exit since there's nothing to block

    print("Blocked domains and paths have been loaded.")
    print(f"Blocked domains: {blocked_domains}")
    print(f"Blocked paths: {blocked_paths}")

proxy_enabled = False

class Logger:
    def __init__(self):
        self.log_file = open("network_log.txt", "a")

    def log_request(self, flow: http.HTTPFlow) -> None:
        source_ip, source_port = flow.client_conn.address
        dest_ip, dest_port = flow.server_conn.address
        
        log_message = f"======= Request =======\n"
        log_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        log_message += f"URL: {flow.request.pretty_url}\n"
        log_message += f"Method: {flow.request.method}\n"
        log_message += f"Host: {flow.request.host}\n"
        log_message += f"Source IP: {source_ip}:{source_port}\n"
        log_message += f"Destination IP: {dest_ip}:{dest_port}\n"
        log_message += f"Port: {flow.request.port}\n"
        log_message += f"Protocol: HTTP\n"
        log_message += f"Event ID: REQUEST\n"
        log_message += f"Severity Level: Info\n"
        log_message += "=======================\n\n"
        
        print(log_message.strip())
        self.log_file.write(log_message)

    def log_response(self, flow: http.HTTPFlow) -> None:
        source_ip, source_port = flow.client_conn.address
        dest_ip, dest_port = flow.server_conn.address
        
        log_message = f"======= Response =======\n"
        log_message += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        log_message += f"URL: {flow.request.pretty_url}\n"
        log_message += f"Method: {flow.request.method}\n"
        log_message += f"Host: {flow.request.host}\n"
        log_message += f"Source IP: {source_ip}:{source_port}\n"
        log_message += f"Destination IP: {dest_ip}:{dest_port}\n"
        log_message += f"Port: {flow.request.port}\n"
        log_message += f"Protocol: HTTP\n"
        log_message += f"Event ID: RESPONSE\n"
        log_message += f"Severity Level: Info\n"
        log_message += "=======================\n\n"
        
        print(log_message.strip())
        self.log_file.write(log_message)

    def done(self):
        self.log_file.close()

logger = Logger()

def enable_proxy():
    global proxy_enabled
    try:
        command_proxy = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "http=127.0.0.1:8080;https=127.0.0.1:8080;ftp=127.0.0.1:8080" /f'
        subprocess.run(command_proxy, shell=True, check=True)

        command_enable = r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f'
        subprocess.run(command_enable, shell=True, check=True)

        proxy_enabled = True
    except subprocess.CalledProcessError as e:
        print(f"Failed to enable proxy: {e}")
        sys.exit(1)

def registry_value_exists(key, value):
    command_check = f'reg query "{key}" /v {value}'
    result = subprocess.run(command_check, shell=True, capture_output=True)
    return result.returncode == 0

def disable_proxy():
    global proxy_enabled
    try:
        proxy_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
        if registry_value_exists(proxy_key, "ProxyServer"):
            command_disable_proxy = f'reg delete "{proxy_key}" /v ProxyServer /f'
            subprocess.run(command_disable_proxy, shell=True, check=True)

        if registry_value_exists(proxy_key, "ProxyEnable"):
            command_disable_enable = f'reg delete "{proxy_key}" /v ProxyEnable /f'
            subprocess.run(command_disable_enable, shell=True, check=True)

        proxy_enabled = False
    except subprocess.CalledProcessError as e:
        print(f"Failed to disable proxy: {e}")
        sys.exit(1)

def start_mitmproxy():
    try:
        enable_proxy()

        command = [
            "mitmdump",
            "--set", "connection_strategy=eager",
            "--set", "stream_large_bodies=1500b",
            "--set", "console_eventlog_verbosity=error",
            "--set", "ssl_insecure=true",
            "-s", __file__
        ]
        mitmdump_process = subprocess.Popen(command)

        try:
            mitmdump_process.wait()
        except KeyboardInterrupt:
            print("\nCtrl+C detected. Stopping and disabling the server...")
            sys.exit(0)
        finally:
            disable_proxy()
    except Exception as e:
        print(f"Error starting mitmdump: {e}")
        disable_proxy()
        sys.exit(1)

def request(flow: http.HTTPFlow) -> None:
    # Load the latest blocked domains and paths
    load_blocked_data()
    
    if flow.request.pretty_url.startswith("http://") or flow.request.pretty_url.startswith("https://"):
        logger.log_request(flow)

        # Check for exact domain match or subdomain match
        if any(flow.request.host == domain or flow.request.host.endswith('.' + domain) for domain in blocked_domains):
            respond_with_custom_html(flow)
            return

        # Check if request path is in blocked paths
        if any(flow.request.path.startswith(path) for path in blocked_paths):
            respond_with_custom_html(flow)
            return

def respond_with_custom_html(flow: http.HTTPFlow):
    """Respond with a custom HTML file."""
    if os.path.exists(custom_html_path):
        with open(custom_html_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        flow.response = http.Response.make(
            403,  # HTTP status code for Forbidden
            html_content,  # Custom HTML content
            {"Content-Type": "text/html"}  # Content type as HTML
        )
    else:
        print(f"Custom HTML file '{custom_html_path}' not found.")
        flow.response = http.Response.make(
            403,  
            b"Blocked by custom proxy",  
            {"Content-Type": "text/plain"} 
        )

def response(flow: http.HTTPFlow) -> None:
    # Log response details
    if flow.response:
        logger.log_response(flow)

def main():
    # Clear and load block list at the start of the program
    load_blocked_data()

    signal.signal(signal.SIGINT, lambda sig, frame: (disable_proxy(), sys.exit(0)))
    print("Starting Server...")
    start_mitmproxy()

if __name__ == "__main__":
    main()
