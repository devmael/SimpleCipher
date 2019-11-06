#!/usr/bin/python3

import tkinter as tk
import tkinter.simpledialog
import tkinter.messagebox
import base64
import hashlib
import os
import getpass
import shutil
from Crypto import Random
from Crypto.Cipher import AES
import re

import argparse


class AESCipher(object):

    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


def encrypt_file(path, key):
    cipher = AESCipher(str(key))

    content = ""

    kind = "<type>file</type>\n"

    with open(path, "r") as f:
        content = f.read()

    with open(path + ".enc", "w+") as f:
        f.write(kind + cipher.encrypt(content).decode("utf-8"))

    os.remove(path)

    pass

def encrypt_directory(path, key):

    if path[-1] == "/":
        path = path[:-1]

    cipher = AESCipher(str(key))
    shutil.make_archive(path, 'zip', path)

    content = ""
    kind = "<type>directory</type>\n"

    with open(path+'.zip', "rb") as f:
        content = f.read()

    encoded = base64.b64encode(content).decode("utf-8")

    with open(path + ".enc", "w+") as f:
        f.write(kind + cipher.encrypt(encoded).decode("utf-8"))

    shutil.rmtree(path)
    os.remove(path+'.zip')

    pass

def decrypt_file(path, key):
    cipher = AESCipher(str(key))

    content = ""

    with open(path, "r") as f:
        f.readline()
        content = f.readline()


    decrypted = cipher.decrypt(content)
    if decrypted == "":
        tkinter.messagebox.showwarning("Error", "Bad password")
        return

    with open(path.replace('.enc',''), "w+") as f:
        f.write(decrypted)

    os.remove(path)

    pass


def decrypt_directory(path, key):
    cipher = AESCipher(str(key))

    content = ""

    with open(path, "r") as f:
        f.readline()
        content = f.readline()

    decrypted = cipher.decrypt(content)
    if decrypted == "":
        tkinter.messagebox.showwarning("Error", "Bad password")
        return

    with open(path.replace('.enc','.zip'), "wb+") as f:
        f.write(base64.b64decode(decrypted))

    shutil.unpack_archive(path.replace('.enc','.zip'), path.replace('.enc',''))

    os.remove(path)
    os.remove(path.replace('.enc','.zip'))

    pass

def test():
    cipher = AESCipher('test')
    cipher_text = cipher.encrypt('yo les potos')
    print(cipher_text)
    print(cipher.decrypt(cipher_text))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input')
    parser.add_argument('-d', '--decrypt')
    args = parser.parse_args()

    tk.Tk().withdraw()
    secret = tkinter.simpledialog.askstring("Password", "Enter password:", show='*')

    if secret == None or secret == "":
        tkinter.messagebox.showwarning("Error", "Password can't be empty.")
        return

    if args.input:
        if os.path.isdir(args.input):  
            encrypt_directory(args.input, secret)
        elif os.path.isfile(args.input):  
            encrypt_file(args.input, secret)
        else:  
            print("It is a special file (socket, FIFO, device file)" )
        
        
    elif args.decrypt:

        kind = ""

        with open(args.decrypt, 'r') as f:
            kind = re.findall("<type>(.*?)</type>", f.readline())[0]
            pass

        if kind == "directory":  
            decrypt_directory(args.decrypt, secret)
        elif kind == "file":  
            decrypt_file(args.decrypt, secret) 
        else:  
            print("It is a special file (socket, FIFO, device file)" )
    else:
        print('err')

if __name__ == "__main__":
    main()