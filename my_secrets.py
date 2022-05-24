from argparse import ArgumentParser

def encryptFile():
    print('File is encrypting')

def decryptFile():
    print('File is decrypting')

def appendToFile():
    print('File is encrypting')
    print('File is decrypting')

parser = ArgumentParser()
mode = {
    'encrypt': encryptFile,
    'decrypt': decryptFile,
    'append': appendToFile,
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
function()
print(files)