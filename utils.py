"""All classes and functions used in main program"""
from base64 import urlsafe_b64encode
from os import listdir
from pathlib import Path
from random import sample
from string import ascii_letters
from dotenv import dotenv_values

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken


def get_salt_from_env() -> str:
    while True:
        try:
            my_salt = dotenv_values()['salt']
            break
        except KeyError:
            with open('.env', mode='a', encoding='utf-8') as settings:
                settings.write(f'salt="{"".join(sample(ascii_letters, k=10))}"\n')

    return my_salt


def generate_code_key(password: str, salt: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512,
        length=32,
        salt=salt.encode('utf-8'),
        iterations=390000
    )

    return urlsafe_b64encode(kdf.derive(bytes(password, 'utf-8')))


class _CommonThings:
    def __init__(self, password: str) -> None:
        self.password = password
        self.fernet = self._generate_fernet(self.password)

    @staticmethod
    def _generate_fernet(password: str, salt: str = None) -> Fernet:
        if salt is None:
            salt = get_salt_from_env()
        key = generate_code_key(password, salt)

        return Fernet(key)

    def execute(self, path: Path) -> None:
        pass


class Encryption(_CommonThings):
    def __init__(self, password: str) -> None:
        super().__init__(password)

    def execute(self, path: Path) -> None:
        self.path = path
        if self.path.suffix != '.dokodu':
            try:
                with open(self.path, 'r', encoding='utf-8') as input_file:
                    content = input_file.read()
            except FileNotFoundError:
                print('This file don\'t exist! You input wrong path')
                return None

            encrypted_file = self.fernet.encrypt(content.encode('utf-8'))
            while True:
                try:
                    with open('encrypted_files.dokodu', 'r', encoding='utf-8') as encrypted_files:
                        self.lines = encrypted_files.readlines()
                        break
                except FileNotFoundError:
                    if not 'encrypted_files.dokodu' in listdir('./'):
                        open('encrypted_files.dokodu', 'w', encoding='utf-8').close()

            try:
                for i, line in enumerate(self.lines):
                    self.lines[i] = Path(line.strip())
            except UnboundLocalError:
                self.lines = []

            if self.path not in self.lines:
                with open('encrypted_files.dokodu', 'a', encoding='utf-8') as encrypted_files:
                    encrypted_files.write(f'{self.path}\n')

            with open(self.path.rename(self.path.with_suffix('.dokodu')), 'w', encoding='utf-8') as result:
                result.write(encrypted_file.decode('utf-8'))

            print(f'File {path} is encrypted')
        else:
            print('This file is not correct suffix - can\'t encrypt file *.dokodu')


class Decryption(_CommonThings):
    def __init__(self, password: str) -> None:
        super().__init__(password)

    def execute(self, path: Path) -> None:
        self.path = path
        try:
            with open('encrypted_files.dokodu', 'r', encoding='utf-8') as checklist:
                for line in checklist:
                    new_path = Path(line.strip())
                    if self.path.with_suffix('.test') == new_path.with_suffix('.test'):
                        new_path = Path(line.strip())
                        break
                    else:
                        new_path = self.path.with_suffix('.txt')

        except FileNotFoundError:
            new_path = self.path.with_suffix('.txt')

        try:
            type(new_path)
        except UnboundLocalError:
            new_path = self.path.with_suffix('.txt')

        try:
            with open(self.path, 'r') as input_file:
                content = input_file.read()

            decrypted_file = self.fernet.decrypt(content.encode('utf-8'))

            with open(self.path.rename(new_path), 'w') as result:
                result.write(decrypted_file.decode('utf-8'))

            print(f'File {path} is decrypted')

        except FileNotFoundError:
            print('This file don\'t exist! You input wrong path')
        except InvalidToken:
            print('This file can\'t be decrypted! You input wrong password')


# def AppendToFile(fernet: Fernet, self.path: Path):
#     print('File is encrypting')

#     print('File is decrypting')
