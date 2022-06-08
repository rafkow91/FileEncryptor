from base64 import urlsafe_b64encode
from os import listdir
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import dotenv_values
from random import sample
from string import ascii_letters
from cryptography.fernet import Fernet
from pathlib import Path


def EncryptFile(fernet: Fernet, file_path: Path):
    if file_path.suffix != '.dokodu':
        with open(file_path, 'r') as input_file:
            content = input_file.read()

        encrypted_file = fernet.encrypt(content.encode('utf-8'))
        if not 'encrypted_files.dokodu' in listdir('./'):
            open('encrypted_files.dokodu', 'w').close()
        with open('encrypted_files.dokodu', 'r') as encrypted_files:
            lines = encrypted_files.readlines()

            for i, line in enumerate(lines):
                lines[i] = Path(line.strip())

            if file_path not in lines:
                with open('encrypted_files.dokodu', 'a') as encrypted_files:
                    encrypted_files.write(f'{file_path}\n')

        with open(file_path.rename(file_path.with_suffix('.dokodu')), 'w') as result:
            result.write(encrypted_file.decode('utf-8'))


def DecryptFile(fernet: Fernet, file_path: Path):
    
    if 'encrypted_files.dokodu' in listdir('./'):
        with open('encrypted_files.dokodu', 'r') as checklist:
            path = None
            for line in checklist:
                path = Path(line.strip())
                if file_path.with_suffix('.test') == path.with_suffix('.test'):
                    break
                else:
                    path = file_path.with_suffix('.txt')
    else:
        path = file_path.with_suffix('.txt')

    with open(file_path, 'r') as input_file:
        content = input_file.read()

    decrypted_file = fernet.decrypt(content.encode('utf-8'))

    with open(file_path.rename(path), 'w') as result:
        result.write(decrypted_file.decode('utf-8'))


def AppendToFile(fernet: Fernet, file_path: Path):
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
        iterations=390000
    )

    return urlsafe_b64encode(kdf.derive(bytes(password, 'utf-8')))
