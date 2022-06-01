from argparse import ArgumentParser
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass

from utils import EncryptFile, DecryptFile, AppendToFile, CodeKey


parser = ArgumentParser()
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

parser.add_argument(
    '-f', '--file',
    help='file or list of files to processing',
    nargs='+'
)

parser.add_argument(
    '-F', '--folder',
    help='folder with files to processing',
)

args = parser.parse_args()

function = mode[args.mode]
files = args.file
folder_path = args.folder

password = getpass()

my_key = CodeKey(password)
fernet = Fernet(my_key)

for i, _ in enumerate(files):
    function(fernet, files[i])
