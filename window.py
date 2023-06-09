import sys
import base64

from PyQt5 import QtWidgets
from ui_frame import Ui_frame
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class Window(QtWidgets.QWidget):
    def __init__(self):
        super().__init__(parent=None)

        self.ui = Ui_frame()
        self.ui.setupUi(self)

        self.setupUi()

        self.algorithm = "des"

    def setupUi(self):
        self.ui.des.clicked.connect(self.des)
        self.ui.aes.clicked.connect(self.aes)
        self.ui.rsa.clicked.connect(self.rsa)

        self.ui.des.click()
        self.ui.encrypt.clicked.connect(self.encrypt)
        self.ui.decrypt.clicked.connect(self.decrypt)

    def des(self):
        self.algorithm = "des"

    def aes(self):
        self.algorithm = "aes"

    def rsa(self):
        self.algorithm = "rsa"


    def encrypt(self):
        if self.algorithm == "des":
            text = self.desEncryption()
        elif self.algorithm == "aes":
            text = self.aesEncryption()
        else:
            text = self.rsaEncryption()

        self.ui.textOut.setPlainText(text.decode())

    def decrypt(self):
        if self.algorithm == "des":
            text = self.desDecryption()
        elif self.algorithm == "aes":
            text = self.aesDecryption()
        else:
            text = self.rsaDecryption()
        
        self.ui.textOut.setPlainText(text.decode())


    def desEncryption(self):
        with open("keys/desKey.key", "rb") as file:
            key = file.read()

        cipher = DES.new(key, DES.MODE_EAX)

        return base64.b64encode(cipher.nonce + cipher.encrypt(self.ui.textIn.toPlainText().encode("utf-8")))

    def aesEncryption(self):
        message = self.ui.textIn.toPlainText().encode("utf-8")
        with open("keys/aesKey.key", "rb") as file:
            content = file.read()
            iv = content[:16]
            key = content[16:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = message + (16 - len(message) % 16) * chr(16 - len(message) % 16).encode()

        return base64.b64encode(cipher.encrypt(padded_message))
    
    def rsaEncryption(self):
        with open("keys/rsaKey.key", "rb") as file:
            key_data = file.read()
            key = RSA.importKey(key_data)

        cipher = PKCS1_OAEP.new(key)

        return cipher.encrypt(self.ui.textIn.toPlainText().encode("utf-8"))
    


    def desDecryption(self):
        message = base64.b64decode(self.ui.textIn.toPlainText().encode("utf-8"))
        with open("keys/desKey.key", "rb") as file:
            key = file.read()

        cipher = DES.new(key, DES.MODE_EAX, nonce=message[:16])

        return cipher.decrypt(message[16:])

    def aesDecryption(self):
        message = base64.b64decode(self.ui.textIn.toPlainText().encode("utf-8"))
        with open("keys/aesKey.key", "rb") as file:
            content = file.read()
            iv = content[:16]
            key = content[16:]

        cipher = AES.new(key, AES.MODE_CBC, iv)

        return cipher.decrypt(message)
    
    def rsaDecryption(self):
        with open("keys/rsapKey.key", "rb") as file:
            key_data = file.read()
            key = RSA.importKey(key_data)

        cipher = PKCS1_OAEP.new(key)
        print(len(self.ui.textIn.toPlainText().encode("utf-8")))
        return cipher.encrypt(self.ui.textIn.toPlainText().encode("utf-8"))



if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)

    window = Window()
    window.show()

    app.exec_()