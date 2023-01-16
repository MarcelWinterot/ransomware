from cryptography.fernet import Fernet as fr
from time import time
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#ByBQJFE_OCJU8_1V9nVlbrBjeaqLUyBH-CdksQpWctg=  key
key = 'xGJjEQ4kjKePpDvnG6Ph4_GdeA-85vPi-vpORJ7GiO8='

def encryptDecryptMessage(message, option):
    cipher = fr(key)
    if option == "encrypt":
        return cipher.encrypt(bytes(message, 'utf-8'))
    elif option == "decrypt":
        return cipher.decrypt(bytes(message, 'utf-8'))

def encryptDecryptFile(filePath, option):
    cipher = fr(key)
    if option == "encrypt":
        with open(filePath, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = cipher.encrypt(file_data)

        with open(filePath, 'wb') as f:
            f.write(encrypted_data)

        print(f'Successfully encrypted {filePath}')
    elif option == "decrypt":
        with open(filePath, 'rb') as f:
            file_data = f.read()
        
        decrypted_data = cipher.decrypt(file_data)

        with open(filePath, 'wb') as f:
            f.write(decrypted_data)

        print(f'Successfully decrypted {filePath}')

def encryptDecryptFolder(folderPath, option, startTime = time(), count = 0):
    cipher = fr(key)
    files = os.listdir(folderPath)
    if option == "encrypt":
        for file in files:
            file = folderPath + "/" + file
            count += 1
            with open(file, "rb") as fileToEncrypt:
                fileData = fileToEncrypt.read()
                encryptData = cipher.encrypt(fileData)
            with open(file, "wb") as fileToEncrypt:
                fileToEncrypt.write(encryptData)
            print("Number of encrypted files:", count, "/", len(files))
    elif option == "decrypt":
        for file in files:
            file = folderPath + "/" + file
            count += 1
            with open(file, "rb") as fileToEncrypt:
                fileData = fileToEncrypt.read()
                encryptData = cipher.decrypt(fileData)
            with open(file, "wb") as fileToEncrypt:
                fileToEncrypt.write(encryptData)
            print("Number of encrypted files:", count, "/", len(files))
    print("It took:", time() - startTime, "seconds")

def advancedFolderEncryption(folderPath, count = 0):
    cipher = fr(key)
    files = os.listdir(folderPath)
    numberOfTextFiles = 0
    for file in files:
        #Check if a file is a folder
        if os.path.isdir(folderPath + "/" + file):
            advancedFolderEncryption(folderPath + "/" + file)
        else:
            file = folderPath + "/" + file
            count += 1
            numberOfTextFiles += 1
            with open(file, "rb") as fileToEncrypt:
                fileData = fileToEncrypt.read()
                encryptData = cipher.encrypt(fileData)
            with open(file, "wb") as fileToEncrypt:
                fileToEncrypt.write(encryptData)
            print("[+] Number of encrypted files in folder:", folderPath, ":", str(count) + "/" + str(numberOfTextFiles))

def advancedFolderDecryption(folderPath, count = 0):
    cipher = fr(key)
    files = os.listdir(folderPath)
    numberOfTextFiles = 0
    for file in files:
        #Check if a file is a folder
        if os.path.isdir(folderPath + "/" + file):
            advancedFolderDecryption(folderPath + "/" + file)
        else:
            file = folderPath + "/" + file
            count += 1
            numberOfTextFiles += 1
            with open(file, "rb") as fileToEncrypt:
                fileData = fileToEncrypt.read()
                encryptData = cipher.decrypt(fileData)
            with open(file, "wb") as fileToEncrypt:
                fileToEncrypt.write(encryptData)
            print("[+] Number of decrypted files in folder:", folderPath, ":", str(count) + "/" + str(numberOfTextFiles))

def advancedFolderEncryptionAES(folderPath, count = 0):
    password = b"pl73{iAniz[5Z^5czVE_D@aF5]YpG,"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'p1[4m3nT',
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    files = os.listdir(folderPath)
    numberOfTextFiles = 0
    for file in files:
        #Check if a file is a folder
        if os.path.isdir(folderPath + "/" + file):
            advancedFolderEncryptionAES(folderPath + "/" + file)
        else:
            file = folderPath + "/" + file
            count += 1
            numberOfTextFiles += 1
            with open(file, "rb") as fileToEncrypt:
                fileData = fileToEncrypt.read()
                encryptData = f.encrypt(fileData)
            with open(file, "wb") as fileToEncrypt:
                fileToEncrypt.write(encryptData)
            print("[+] Number of encrypted files in folder:", folderPath, ":", str(count) + "/" + str(numberOfTextFiles))

def advancedFolderDecryptionAES(folderPath, count = 0):
    password = b"pl73{iAniz[5Z^5czVE_D@aF5]YpG,"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'p1[4m3nT',
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    files = os.listdir(folderPath)
    numberOfTextFiles = 0
    for file in files:
        #Check if a file is a folder
        if os.path.isdir(folderPath + "/" + file):
            advancedFolderDecryptionAES(folderPath + "/" + file)
        else:
            file = folderPath + "/" + file
            count += 1
            numberOfTextFiles += 1
            with open(file, "rb") as fileToEncrypt:
                fileData = fileToEncrypt.read()
                encryptData = f.decrypt(fileData)
            with open(file, "wb") as fileToEncrypt:
                fileToEncrypt.write(encryptData)
            print("[+] Number of decrypted files in folder:", folderPath, ":", str(count) + "/" + str(numberOfTextFiles))

def combinedEncryption(folderPath):
    advancedFolderEncryption(folderPath)
    print("[+] First encryption done")
    advancedFolderEncryptionAES(folderPath)
    print("[+] Second encryption done")

def combinedDecryption(folderPath):
    advancedFolderDecryptionAES(folderPath)
    print("[+] First decryption done")
    advancedFolderDecryption(folderPath)
    print("[+] Second decryption done")

file = "path to file"
dirPath = "./folder"

combinedEncryption(dirPath)
