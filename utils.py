from base64 import urlsafe_b64encode
from email import contentmanager
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import dotenv_values
from random import sample
from string import ascii_letters
from cryptography.fernet import Fernet
from os import makedirs, listdir

# TODO: dorobić obsługę folderów!!
def EncryptFile(fernet: Fernet, filename: str, dir_path: str = None):
    if dir_path is None and not 'encrypted' in listdir():
        makedirs('encrypted')
    with open(filename, 'r') as input_file:
        content = input_file.read()

    encrypted_file = fernet.encrypt(content.encode('utf-8'))

    with open(f'encrypted/{filename}.dokodu', 'w') as result:
        result.write(encrypted_file.decode('utf-8'))


def DecryptFile(fernet: Fernet, filename: str, dir_path: str = None):
    print('File is decrypting')
    if dir_path is None and not 'decrypted' in listdir():
        makedirs('decrypted')
    with open(filename, 'r') as input_file:
        content = input_file.read()

    decrypted_file = fernet.decrypt(content.encode('utf-8'))

    with open(f'decrypted/{filename[:-7]}', 'w') as result:
        result.write(decrypted_file.decode('utf-8'))

def AppendToFile(fernet: Fernet):
    print('File is encrypting')
    print('File is decrypting')


def GetSaltFromEnv():
    while True:
        try:
            my_salt = dotenv_values()['salt']
            break
        except KeyError:
            with open('.env', mode='a') as settings:
                settings.write(f'salt="{"".join(sample(ascii_letters, k=10))}"\n')

    return my_salt


def CodeKey(password):
    salt = GetSaltFromEnv()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512,
        length=32,
        salt=salt.encode('utf-8'),
        iterations=100
    )

    return urlsafe_b64encode(kdf.derive(bytes(password, 'utf-8')))
