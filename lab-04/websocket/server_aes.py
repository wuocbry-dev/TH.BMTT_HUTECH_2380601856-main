import tornado.web
import tornado.ioloop
import tornado.websocket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# Fixed AES Key for demonstration (16 bytes)
AES_KEY = b'HutechSecurityKey'

class AESWebSocketServer(tornado.websocket.WebSocketHandler):
    def open(self):
        print("Client connected to AES WebSocket Server", flush=True)

    def on_message(self, message):
        print(f"Received from client: {message}", flush=True)
        
        # Encrypt the message using AES-CBC
        iv = os.urandom(16)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        padded_msg = pad(message.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_msg)
        
        # Combine IV and ciphertext, send as hex string
        encrypted_payload = (iv + ciphertext).hex()
        
        print(f"Encrypted message: {encrypted_payload}", flush=True)
        self.write_message(encrypted_payload)

    def on_close(self):
        print("Client disconnected", flush=True)

    def check_origin(self, origin):
        return True # Allow connections from anywhere

def main():
    app = tornado.web.Application([
        (r"/websocket_aes/", AESWebSocketServer),
    ])
    app.listen(8889)
    print("AES WebSocket Server listening on ws://localhost:8889/websocket_aes/", flush=True)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()
