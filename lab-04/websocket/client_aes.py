import sys
import tornado.ioloop
import tornado.websocket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

AES_KEY = b'HutechSecurityKey'

class AESWebSocketClient:
    def __init__(self, io_loop):
        self.io_loop = io_loop
        self.connection = None

    def start(self):
        self.connect()

    def connect(self):
        print("Connecting to AES WebSocket Server...", flush=True)
        future = tornado.websocket.websocket_connect(
            url="ws://localhost:8889/websocket_aes/"
        )
        future.add_done_callback(self.on_connect)

    def on_connect(self, future):
        try:
            self.connection = future.result()
            print("Connected successfully!", flush=True)
            self.send_message_loop()
        except Exception as e:
            print(f"Connection failed: {e}. Retrying in 3 seconds...", flush=True)
            self.io_loop.call_later(3, self.connect)

    def send_message_loop(self):
        sys.stdout.write("Enter message to encrypt: ")
        sys.stdout.flush()
        
        # Read from stdin asynchronously
        def read_stdin():
            message = sys.stdin.readline().strip()
            if message:
                self.connection.write_message(message)
                self.connection.read_message(callback=self.on_message)
            else:
                self.send_message_loop()
        
        self.io_loop.add_callback(read_stdin)

    def on_message(self, future):
        try:
            encrypted_payload_hex = future.result()
            if encrypted_payload_hex is None:
                print("\nDisconnected by server.", flush=True)
                self.io_loop.stop()
                return
            
            print(f"Received (Encrypted Hex): {encrypted_payload_hex}", flush=True)
            
            # Decrypt to verify
            payload = bytes.fromhex(encrypted_payload_hex)
            iv = payload[:16]
            ciphertext = payload[16:]
            
            cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
            
            print(f"Decrypted to verify: {decrypted}", flush=True)
            print("-" * 40, flush=True)
            
            self.send_message_loop()
        except Exception as e:
            print(f"Error: {e}", flush=True)
            self.io_loop.stop()

def main():
    io_loop = tornado.ioloop.IOLoop.current()
    client = AESWebSocketClient(io_loop)
    io_loop.add_callback(client.start)
    io_loop.start()

if __name__ == "__main__":
    main()
