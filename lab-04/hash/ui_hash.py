import sys
import hashlib
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QComboBox, QTextEdit, QMessageBox
from Crypto.Hash import SHA3_256

class UIHash(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hash Algorithms UI - Security Lab")
        self.resize(550, 400)
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        layout = QVBoxLayout()

        # Input text
        layout.addWidget(QLabel("Enter text to hash:"))
        self.txt_input = QLineEdit()
        self.txt_input.setPlaceholderText("Type some text here...")
        layout.addWidget(self.txt_input)

        # Algorithm Selection
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel("Select Algorithm:"))
        self.cbo_algo = QComboBox()
        self.cbo_algo.addItems(["MD5 (Custom)", "MD5 (Library)", "SHA-256", "SHA-3", "Blake2"])
        algo_layout.addWidget(self.cbo_algo)
        layout.addLayout(algo_layout)

        # Action Button
        self.btn_hash = QPushButton("Compute Hash")
        self.btn_hash.clicked.connect(self.compute_hash)
        layout.addWidget(self.btn_hash)

        # Result Display
        layout.addWidget(QLabel("Resulting Hash Value (Hex):"))
        self.txt_result = QTextEdit()
        self.txt_result.setReadOnly(True)
        self.txt_result.setStyleSheet("font-family: Consolas; font-size: 11pt; color: #b11d1d;")
        layout.addWidget(self.txt_result)

        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    # Custom MD5 Implementation (same as in md5_hash.py)
    def custom_md5(self, message):
        def left_rotate(value, shift):
            return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF
        
        a = 0x67452301
        b = 0xEFCDAB89
        c = 0x98BADCFE
        d = 0x10325476

        original_length = len(message)
        message += b'\x80'
        while len(message) % 64 != 56:
            message += b'\x00'
        message += original_length.to_bytes(8, 'little')

        for i in range(0, len(message), 64):
            block = message[i:i+64]
            words = [int.from_bytes(block[j:j+4], 'little') for j in range(0, 64, 4)]
            a0, b0, c0, d0 = a, b, c, d

            for j in range(64):
                if j < 16:
                    f = (b & c) | ((~b) & d)
                    g = j
                elif j < 32:
                    f = (d & b) | ((~d) & c)
                    g = (5 * j + 1) % 16
                elif j < 48:
                    f = b ^ c ^ d
                    g = (3 * j + 5) % 16
                else:
                    f = c ^ (b | (~d))
                    g = (7 * j) % 16

                temp = d
                d = c
                c = b
                b = (b + left_rotate((a + f + 0x5A827999 + words[g]) & 0xFFFFFFFF, 3)) & 0xFFFFFFFF
                a = temp

            a = (a + a0) & 0xFFFFFFFF
            b = (b + b0) & 0xFFFFFFFF
            c = (c + c0) & 0xFFFFFFFF
            d = (d + d0) & 0xFFFFFFFF

        return '{:08x}{:08x}{:08x}{:08x}'.format(a, b, c, d)

    def compute_hash(self):
        input_text = self.txt_input.text()
        if not input_text:
            QMessageBox.warning(self, "Warning", "Please enter some text to hash.")
            return

        algo = self.cbo_algo.currentText()
        data_bytes = input_text.encode('utf-8')

        try:
            if algo == "MD5 (Custom)":
                result = self.custom_md5(data_bytes)
            elif algo == "MD5 (Library)":
                result = hashlib.md5(data_bytes).hexdigest()
            elif algo == "SHA-256":
                result = hashlib.sha256(data_bytes).hexdigest()
            elif algo == "SHA-3":
                sha3_hash = SHA3_256.new(data_bytes)
                result = sha3_hash.hexdigest()
            elif algo == "Blake2":
                result = hashlib.blake2b(data_bytes, digest_size=64).hexdigest()
            else:
                result = "Unknown Algorithm"

            self.txt_result.setPlainText(result.upper())
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Hashing failed: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = UIHash()
    window.show()
    sys.exit(app.exec_())
