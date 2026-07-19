import ssl
import json
from colorama import Fore

class TLS:
  def __init__(self, ciphers, group):
    self.ciphers = ciphers
    self.group = group

  def open_cipher_suite(self):
      try:
          with open("tls_ciphers.json", "r") as file:
              tls-ciphers = json.load(file)
      except FileNotFoundError:
          print("Error: 'tls_ciphers.json' file was not found.")
          
  def tls_server(self):
      try:
         
          
           
  def tls_client(self):
     try:
        context.load_verify_locations(cafile=cert_file)
    except Exception as e:
  print('')
     
  def tls_connect(self):
     return
  
  def tls_handshake(self):
     return
  
  def tls_channel(self):
     return
     
 

