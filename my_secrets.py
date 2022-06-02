from argparse import ArgumentParser
from cryptography.fernet import Fernet
from getpass import getpass
from os import walk
from pathlib import Path

from utils import EncryptFile, DecryptFile, AppendToFile, CodeKey

if __name__ == '__main__':

    parser = ArgumentParser(
        description='App can encrypt and decrypt files \
            | password is getting on every start app, salt is saved in .env file')
    mode = {
        'encrypt': EncryptFile,
        'decrypt': DecryptFile,
        'append': AppendToFile,
    }
    parser.add_argument(
        '-m', '--mode',
        help='encrypt given file or files | decrypt encrypted file or files | append -> decrypt file, append text and encrypt the file again',
        choices=mode.keys(),
        default='encrypt'
    )

    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        '-f', '--file',
        help='file or list of files to processing',
        nargs='+'
    )

    group.add_argument(
        '-d', '--dir',
        help='path to folder with files to processing',
    )

    args = parser.parse_args()

    function = mode[args.mode]
    files = args.file
    folder_path = args.dir

    if not files:
        files = []
        for path, _, files_in_path in walk(folder_path):
            try:
                for file_path in files_in_path:
                    files.append(f'{path}/{file_path}')
            except:
                continue
            
    password = getpass()

    my_key = CodeKey(password)
    fernet = Fernet(my_key)
    for file_path in files:
        path = Path(file_path)
        function(fernet, path)
