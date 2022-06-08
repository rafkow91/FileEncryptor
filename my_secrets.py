"""File encryptor - console app to encrypt and decrypt files"""
from argparse import ArgumentParser
from getpass import getpass

from os import walk
from pathlib import Path

from utils import Encryption, Decryption

if __name__ == '__main__':

    parser = ArgumentParser(
        description='App can encrypt and decrypt files \
            | password is getting on every start app, salt is saved in .env file')
    mode = {
        'encrypt': Encryption,
        'decrypt': Decryption,
        'append': print,
    }
    parser.add_argument(
        '-m', '--mode',
        help='encrypt given file or files \
            | decrypt encrypted file or files \
            | append -> decrypt file, append text and encrypt the file again',
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
    password =getpass()

    if not files:
        files = []
        for path, _, files_in_path in walk(folder_path):
            for file_path in files_in_path:
                files.append(f'{path}/{file_path}')

    for file_path in files:
        path = Path(file_path)
        action = function(password)
        action.execute(path)
