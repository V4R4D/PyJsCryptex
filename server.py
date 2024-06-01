
#!/usr/bin/env python

import os
import json
import binascii
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
from cgi import parse_header, parse_multipart
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# ------------------------------
# DEFINE Encryption Class
class Cryptor:
    '''
    Provide encryption and decryption function.
    
    Padding PKCS#7: 
    http://www.ietf.org/rfc/rfc2315.txt
    
    The key to make cryptography work is:
    1. Use MODE_CFB.
    2. Use Pkcs7 padding as per RFC 2315
    '''

    # AES-256 key (32 bytes)
    KEY = binascii.unhexlify("01ab38d5e05c92aa098921d9d4626107133c7e2ab0e4849558921ebcc242bcb0")
    BLOCK_SIZE = 16

    @staticmethod
    def pad_string(in_string: bytes) -> bytes:
        '''Pad an input string according to PKCS#7'''
        padder = padding.PKCS7(Cryptor.BLOCK_SIZE * 8).padder()
        padded_data = padder.update(in_string) + padder.finalize()
        return padded_data

    @staticmethod
    def unpad_string(in_string: bytes) -> bytes:
        '''Remove the PKCS#7 padding from a text string'''
        unpadder = padding.PKCS7(Cryptor.BLOCK_SIZE * 8).unpadder()
        unpadded_data = unpadder.update(in_string) + unpadder.finalize()
        return unpadded_data

    @staticmethod
    def generate_iv(size: int = 16) -> bytes:
        return os.urandom(size)

    @classmethod
    def encrypt(cls, in_string: bytes, in_key: bytes, in_iv: bytes = None) -> tuple:
        '''
        Return encrypted string.
        @in_string: Simple str to be encrypted
        @key: bytes key
        @iv: bytes iv
        '''
        key = in_key
        if in_iv is None:
            iv = cls.generate_iv()
        else:
            iv = in_iv

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = cls.pad_string(in_string)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        return iv, encrypted_data

    @classmethod
    def decrypt(cls, in_encrypted: bytes, in_key: bytes, in_iv: bytes) -> bytes:
        '''
        Return decrypted string.
        @in_encrypted: encrypted bytes
        @key: bytes key
        @iv: bytes iv
        '''
        key = in_key
        iv = in_iv
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(in_encrypted) + decryptor.finalize()
        return cls.unpad_string(decrypted_data)


# ------------------------------
# DEFINE HTTP Handler
class EncryptHandler(BaseHTTPRequestHandler):
    
    PORT_NUMBER = 8087
    SCRIPT_PATH = '/home/dark_soul/python_learning/enc-dec/UserDataManager'
    # SCRIPT_PATH = os.path.dirname(__file__)
	
    
    def _return_http_code(self, http_code: int):
        self.send_response(http_code)
        self.end_headers()
    
    def _return_file(self, in_file: str):
        if os.path.exists(in_file):
            with open(in_file, 'r') as f:
                self.send_response(200)
                if in_file.endswith(".html"):
                    self.send_header('Content-type', "text/html")
                elif in_file.endswith(".js"):
                    self.send_header('Content-type', "text/javascript")
                else:
                    self.send_header('Content-type', "text/plain")
                self.end_headers()
                self.wfile.write(f.read().encode('utf-8'))
        else:
            self._return_http_code(404)
    
    def _return_json(self, in_dict: dict):
        '''Send JSON back from a dictionary'''
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(in_dict).encode('utf-8'))
    
    def do_GET(self):
        '''
        Serve static .html and .js files
        '''
        request_path = self.path
        if request_path == "/":
            self._return_file(os.path.join(self.SCRIPT_PATH, "index.html"))
        elif request_path.endswith(".html") or request_path.endswith(".js"):
            self._return_file(os.path.join(self.SCRIPT_PATH, request_path.lstrip('/')))
        else:
            self._return_http_code(404)
        return
    
    def parse_POST(self):
        '''
        parse POST body
        '''
        ctype, pdict = parse_header(self.headers.get('content-type'))
        if ctype == 'multipart/form-data':
            postvars = parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers.get('content-length'))
            postvars = parse_qs(self.rfile.read(length), keep_blank_values=1)
        else:
            postvars = {}
        return postvars

    def do_POST(self):
        if self.path == "/encrypt":
            postvars = self.parse_POST()
            if postvars:
                to_encrypt = ''.join(postvars[b'to_encrypt'][0].decode())
                iv, encrypted = Cryptor.encrypt(to_encrypt.encode(), Cryptor.KEY)
                result = {
                    "key": binascii.hexlify(Cryptor.KEY).decode(),
                    "iv": binascii.hexlify(iv).decode(),
                    "ciphertext": binascii.b2a_base64(encrypted).rstrip().decode()
                }
                self._return_json(result)
            else:
                self._return_http_code(500)
        else:
            self._return_http_code(404)
        return

# ------------------------------
# START WEB SERVER
def run_server():
    try:
        # Create a web server and define the handler to manage the
        # incoming request
        server = HTTPServer(('', EncryptHandler.PORT_NUMBER), EncryptHandler)
        print(f'Started httpserver on port {EncryptHandler.PORT_NUMBER}')
        
        # Wait forever for incoming http requests
        server.serve_forever()

    except KeyboardInterrupt:
        print('^C received, shutting down the web server')
        server.socket.close()

if __name__ == "__main__":
    run_server()

