import hashlib
import os
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, \
    QWidget, QFileDialog, QComboBox, QMessageBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def transform_file(operation, encryption_algorithm, block_mode, input_file, password):
    password = hashlib.sha256(password.encode()).digest()
    if encryption_algorithm == 'AES':
        with open(input_file, 'rb') as infile:
            iv = infile.read(16) if operation == 'decrypt' else os.urandom(16)
            cipher = algorithms.AES(password)
            mode = getattr(modes, block_mode)(iv)
            transform = Cipher(cipher, mode, backend=default_backend()).encryptor() if operation == 'encrypt' else \
                Cipher(cipher, mode, backend=default_backend()).decryptor()
            outfile_name = input_file[:-4] if operation == 'decrypt' else input_file + '.enc'
            with open(outfile_name, 'wb') as outfile:
                if operation == 'encrypt':
                    outfile.write(iv)
                while True:
                    chunk = infile.read(64 * 1024)
                    if len(chunk) == 0:
                        break
                    elif operation == 'encrypt' and len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    outfile.write(transform.update(chunk))
                outfile.write(transform.finalize())

encrypt_file = lambda ea, bm, infile, pw: transform_file('encrypt', ea, bm, infile, pw)
decrypt_file = lambda ea, bm, infile, pw: transform_file('decrypt', ea, bm, infile, pw)

class FileCryptorGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.algorithm_list = ['AES']
        self.block_mode_list = ['CBC', 'CFB', 'OFB']
        self.initUI()

    def initUI(self):
        self.setWindowTitle('File Cryptor')

        layout = QVBoxLayout()

        self.select_algorithm_label = QLabel('Select Algorithm:')
        layout.addWidget(self.select_algorithm_label)

        self.select_algorithm_combo = QComboBox()
        self.select_algorithm_combo.addItems(self.algorithm_list)
        layout.addWidget(self.select_algorithm_combo)

        self.select_block_mode_label = QLabel('Select Block Mode:')
        layout.addWidget(self.select_block_mode_label)

        self.select_block_mode_combo = QComboBox()
        self.select_block_mode_combo.addItems(self.block_mode_list)
        layout.addWidget(self.select_block_mode_combo)

        self.key_label = QLabel('Key:')
        layout.addWidget(self.key_label)

        key_hbox = QHBoxLayout()
        self.key_edit = QLineEdit()
        self.key_edit.setEchoMode(QLineEdit.Password)
        key_hbox.addWidget(self.key_edit)

        self.toggle_key_visibility_button = QPushButton('Show')
        self.toggle_key_visibility_button.setCheckable(True)
        self.toggle_key_visibility_button.clicked.connect(self.toggle_key_visibility)
        key_hbox.addWidget(self.toggle_key_visibility_button)
        layout.addLayout(key_hbox)

        self.input_file_label = QLabel('Input File or Directory:')
        layout.addWidget(self.input_file_label)

        input_file_hbox = QHBoxLayout()
        self.input_file_edit = QLineEdit()
        input_file_hbox.addWidget(self.input_file_edit)

        self.input_file_button = QPushButton('Browse')
        self.input_file_button.clicked.connect(self.browse_input_file)
        input_file_hbox.addWidget(self.input_file_button)
        layout.addLayout(input_file_hbox)

        self.encrypt_button = QPushButton('Encrypt')
        self.encrypt_button.clicked.connect(self.encrypt_file_gui)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton('Decrypt')
        self.decrypt_button.clicked.connect(self.decrypt_file_gui)
        layout.addWidget(self.decrypt_button)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def browse_input_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, 'Open File', "", "All Files (*)")
        self.input_file_edit.setText(file_name)

    def toggle_key_visibility(self):
        if self.toggle_key_visibility_button.isChecked():
            self.key_edit.setEchoMode(QLineEdit.Normal)
            self.toggle_key_visibility_button.setText('Hide')
        else:
            self.key_edit.setEchoMode(QLineEdit.Password)
            self.toggle_key_visibility_button.setText('Show')

    def encrypt_file_gui(self):
        encryption_algorithm = self.select_algorithm_combo.currentText()
        block_mode = self.select_block_mode_combo.currentText()
        input_file = self.input_file_edit.text()
        key = self.key_edit.text()
        if input_file and key:
            encrypt_file(encryption_algorithm, block_mode, input_file, key)
            QMessageBox.information(self, "Success", "File encrypted successfully.")
        else:
            QMessageBox.warning(self, "Warning", "Please provide a valid file and key.")

    def decrypt_file_gui(self):
        encryption_algorithm = self.select_algorithm_combo.currentText()
        block_mode = self.select_block_mode_combo.currentText()
        input_file = self.input_file_edit.text()
        key = self.key_edit.text()
        if input_file and key:
            decrypt_file(encryption_algorithm, block_mode, input_file, key)
            QMessageBox.information(self, "Success", "File decrypted successfully.")
        else:
            QMessageBox.warning(self, "Warning", "Please provide a valid file and key.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    file_cryptor_gui = FileCryptorGUI()
    file_cryptor_gui.show()
    sys.exit(app.exec_())