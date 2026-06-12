import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QGroupBox, QMessageBox
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

class UIDHKeyPair(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Diffie-Hellman Key Exchange UI - Security Lab")
        self.resize(700, 600)
        
        self.server_parameters = None
        self.server_private_key = None
        self.server_public_key = None
        
        self.client_private_key = None
        self.client_public_key = None
        self.shared_secret = None

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout()

        # Server Group
        server_group = QGroupBox("Server Side")
        server_layout = QVBoxLayout()
        
        server_btn_layout = QHBoxLayout()
        self.btn_gen_server = QPushButton("Generate DH Parameters & Server Keys")
        self.btn_gen_server.clicked.connect(self.generate_server_keys)
        server_btn_layout.addWidget(self.btn_gen_server)
        server_layout.addLayout(server_btn_layout)

        server_layout.addWidget(QLabel("Server Public Key (PEM):"))
        self.txt_server_pub = QTextEdit()
        self.txt_server_pub.setReadOnly(True)
        server_layout.addWidget(self.txt_server_pub)
        
        server_group.setLayout(server_layout)
        main_layout.addWidget(server_group)

        # Client Group
        client_group = QGroupBox("Client Side")
        client_layout = QVBoxLayout()

        client_btn_layout = QHBoxLayout()
        self.btn_gen_client = QPushButton("Generate Client Keys & Derive Shared Secret")
        self.btn_gen_client.clicked.connect(self.generate_client_keys)
        self.btn_gen_client.setEnabled(False)
        client_btn_layout.addWidget(self.btn_gen_client)
        client_layout.addLayout(client_btn_layout)

        client_layout.addWidget(QLabel("Client Public Key (PEM):"))
        self.txt_client_pub = QTextEdit()
        self.txt_client_pub.setReadOnly(True)
        client_layout.addWidget(self.txt_client_pub)

        client_group.setLayout(client_layout)
        main_layout.addWidget(client_group)

        # Shared Secret Group
        secret_group = QGroupBox("Derived Shared Secret")
        secret_layout = QVBoxLayout()
        self.txt_secret = QTextEdit()
        self.txt_secret.setReadOnly(True)
        self.txt_secret.setMaximumHeight(80)
        secret_layout.addWidget(self.txt_secret)
        secret_group.setLayout(secret_layout)
        main_layout.addWidget(secret_group)

        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def generate_server_keys(self):
        try:
            self.server_parameters = dh.generate_parameters(generator=2, key_size=2048)
            self.server_private_key = self.server_parameters.generate_private_key()
            self.server_public_key = self.server_private_key.public_key()
            
            pem = self.server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            self.txt_server_pub.setPlainText(pem)
            self.btn_gen_client.setEnabled(True)
            QMessageBox.information(self, "Success", "Server DH parameters and key pair generated successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate server keys: {str(e)}")

    def generate_client_keys(self):
        if not self.server_public_key:
            return
        
        try:
            parameters = self.server_public_key.parameters()
            self.client_private_key = parameters.generate_private_key()
            self.client_public_key = self.client_private_key.public_key()
            
            client_pem = self.client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            self.txt_client_pub.setPlainText(client_pem)
            
            # Exchange key
            self.shared_secret = self.client_private_key.exchange(self.server_public_key)
            self.txt_secret.setPlainText(self.shared_secret.hex().upper())
            
            QMessageBox.information(self, "Success", "Client DH keys generated and Shared Secret derived successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to derive shared secret: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = UIDHKeyPair()
    window.show()
    sys.exit(app.exec_())
