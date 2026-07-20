import ssl
import socket
import json
from colorama import Fore
from latency_monitor import LatencyMonitor

class TLS:
  def __init__(self, ciphers, group):
    self.cipher = ciphers
    self.group = group


  def open_cipher_suite(self):
      try:
          with open('tls_ciphers.json', 'r') as file:
              config = json.load(file)
          cipher_suites = config["cipher_suites"]
          self.cipher_suites = cipher_suites
          print('Available cipher_suites')
      except FileNotFoundError:
          print(Fore.RED + "Error: 'tls_ciphers.json' file was not found.")
          return None
          
  def tls_server(self):
    try:
        self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.server_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.server_context.load_cert_chain(certfile="mycertfile", keyfile="mykeyfile")
        self.bindsocket = socket.socket()
        self.bindsocket.bind(('127.0.0.1', 8443))
        self.bindsocket.listen(5)
        print(Fore.GREEN + 'Success: TLS Server Created!')
        return True
    except Exception as e:
        print(Fore.RED + 'Error: TLS Server Failed!')
        return None
    
                    
  def tls_client(self):
    try:
        self.client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.client_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.client_context.load_verify_locations(cafile='certificate.pem')
        print(Fore.GREEN + 'Success: TLS Client Node Created')
        return True
    except Exception as e:
        print(Fore.RED + 'Error: TLS Client Node Failed!')
        return None


  def tls_server_connect(self):
    try:
        newsocket, fromaddr = self.bindsocket.accept()
        ssock = self.server_context.wrap_socket(newsocket, server_side=True)
        self.conn = ssock
        self.addr = fromaddr
        print(Fore.GREEN + 'Success: TLS Connection Made for Server!')
        return True
    except Exception as e:
        print(Fore.RED + 'Error: TLS Connection Failed for Server!')
        return None

    
  def tls_client_connect(self):
    try:
        sock = socket.create_connection(('127.0.0.1', 8443))
        ssock = self.client_context.wrap_socket(sock, server_hostname='localhost')
        self.conn = ssock
        print(Fore.GREEN + 'Success: TLS Connection Made for Client!')
        return True
    except Exception as e:
        print(Fore.RED + 'Error: TLS Connection Failed for Client!')
        return False
  

  def confirm_tls_handshake(self):
    try:
        cipher_name = self.conn.cipher()[0]
        if cipher_name not in self.cipher_suites:
            print(Fore.YELLOW + f'Warning: negotiated {cipher_name}, not in expected list')
        print(Fore.GREEN + f'Success: negotiated {cipher_name}, {self.conn.version()}')
        return True
    except Exception as e:
        print(Fore.RED + 'Error: TLS Handshake Failed!')
        return None
  

  def tls_channel(self, data):
    try:
        self.conn.sendall(data)
        print(Fore.GREEN + 'Success: TLS Channel Connected!')
        return True
    except Exception as e:
        print(Fore.RED + 'Error: TLS Channel Failed!')
        return None
