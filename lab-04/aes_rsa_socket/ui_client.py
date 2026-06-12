import sys
import socket
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
from PyQt5.QtCore import pyqtSignal, QObject
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

class Communicate(QObject):
    message_received = pyqtSignal(str, str) # (plain, cipher_hex)
    status_changed = pyqtSignal(str)

class UIClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Socket Client (AES & RSA) - Security Lab")
        self.resize(600, 500)
        
        self.client_socket = None
        self.aes_key = None
        self.comm = Communicate()
        self.comm.message_received.connect(self.display_message)
        self.comm.status_changed.connect(self.update_status)

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        layout = QVBoxLayout()

        # Connection Bar
        conn_layout = QHBoxLayout()
        self.lbl_status = QLabel("Status: Disconnected")
        self.btn_connect = QPushButton("Connect to Server")
        self.btn_connect.clicked.connect(self.connect_to_server)
        conn_layout.addWidget(self.lbl_status)
        conn_layout.addWidget(self.btn_connect)
        layout.addLayout(conn_layout)

        # Keys Information
        self.lbl_keys = QLabel("AES Key: None\nRSA Key: Uninitialized")
        self.lbl_keys.setWordWrap(True)
        self.lbl_keys.setStyleSheet("background-color: #f0f0f0; border: 1px solid #ccc; padding: 5px;")
        layout.addWidget(self.lbl_keys)

        # Chat display
        layout.addWidget(QLabel("Chat Log & Crypto details:"))
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        layout.addWidget(self.txt_log)

        # Message Input
        msg_layout = QHBoxLayout()
        self.txt_msg = QLineEdit()
        self.txt_msg.setPlaceholderText("Enter message...")
        self.txt_msg.returnPressed.connect(self.send_message)
        self.btn_send = QPushButton("Send")
        self.btn_send.clicked.connect(self.send_message)
        self.btn_send.setEnabled(False)
        msg_layout.addWidget(self.txt_msg)
        msg_layout.addWidget(self.btn_send)
        layout.addLayout(msg_layout)

        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(("localhost", 12345))
            self.comm.status_changed.emit("Status: Connecting & Exchange Keys...")
            
            # Start key exchange thread
            threading.Thread(target=self.key_exchange, daemon=True).start()
        except Exception as e:
            QMessageBox.critical(self, "Connection Error", f"Cannot connect: {str(e)}")
            self.comm.status_changed.emit("Status: Disconnected")

    def key_exchange(self):
        try:
            # Generate client RSA key
            client_key = RSA.generate(2048)
            
            # Receive server's public key
            server_pub_key_bytes = self.client_socket.recv(2048)
            server_public_key = RSA.import_key(server_pub_key_bytes)
            
            # Send client's public key
            self.client_socket.send(client_key.publickey().export_key(format="PEM"))
            
            # Receive encrypted AES key
            encrypted_aes_key = self.client_socket.recv(2048)
            cipher_rsa = PKCS1_OAEP.new(client_key)
            self.aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            
            self.comm.status_changed.emit("Status: Connected (Secure)")
            self.lbl_keys.setText(f"AES Key (Hex): {self.aes_key.hex()}\nRSA Public Key: Loaded successfully")
            
            # Enable send buttons
            self.btn_send.setEnabled(True)
            self.btn_connect.setEnabled(False)

            # Start receiving thread
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.comm.status_changed.emit(f"Status: Key Exchange Failed - {str(e)}")

    def encrypt_message(self, message):
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
        return cipher.iv + ciphertext

    def decrypt_message(self, encrypted_message):
        iv = encrypted_message[:AES.block_size]
        ciphertext = encrypted_message[AES.block_size:]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_message.decode()

    def send_message(self):
        message = self.txt_msg.text().strip()
        if not message or not self.aes_key:
            return
        
        try:
            encrypted = self.encrypt_message(message)
            self.client_socket.send(encrypted)
            self.txt_log.append(f"<b>You (Plain):</b> {message}")
            self.txt_log.append(f"<font color='blue'><b>You (Cipher Hex):</b> {encrypted.hex()}</font>")
            self.txt_log.append("-" * 40)
            self.txt_msg.clear()
            if message == "exit":
                self.client_socket.close()
                sys.exit(0)
        except Exception as e:
            QMessageBox.critical(self, "Send Error", str(e))

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    break
                decrypted = self.decrypt_message(encrypted_message)
                self.comm.message_received.emit(decrypted, encrypted_message.hex())
            except Exception:
                break
        self.comm.status_changed.emit("Status: Disconnected")
        self.btn_send.setEnabled(False)
        self.btn_connect.setEnabled(True)

    def display_message(self, plain, cipher_hex):
        self.txt_log.append(f"<b>Partner (Plain):</b> {plain}")
        self.txt_log.append(f"<font color='green'><b>Partner (Cipher Hex):</b> {cipher_hex}</font>")
        self.txt_log.append("-" * 40)

    def update_status(self, status):
        self.lbl_status.setText(status)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = UIClient()
    window.show()
    sys.exit(app.exec_())
