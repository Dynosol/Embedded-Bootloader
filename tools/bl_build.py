#!/usr/bin/env python
"""
Bootloader Build Tool

This tool generates the cryptographic keys used throughout the process
and is responsible for building the bootloader.
"""
import argparse
import os
import pathlib
import shutil
import subprocess

from Crypto.Hash import HMAC, SHA256
import struct

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

FILE_DIR = pathlib.Path(__file__).parent.absolute()

    
def write_secret():
    """
    Generates 16-byte AES128-GCM key and 32-byte HMAC key.
    Writes both keys into ./secret_build_output.txt for fw_protect to access.
    Writes both keys into ../bootloader/src/secrets.h for bootloader.c to access.
    Return:
        None
    """
    # Generate both keys with random hexes
    aes_key = os.urandom(16).hex()
    hmackey = os.urandom(32).hex()
    
    # Writes keys into secret_build_output.tx
    f = open("secret_build_output.txt", "w")
    f.write(f"{aes_key}\n{hmackey}")
    f.close()
    
    # Writes keys into ../bootloader/src/secrets.h
    with open ('../bootloader/src/secrets.h', 'w') as fp:
        
        array1 = list(map(''.join, zip(*[iter(aes_key)]*2)))
        array2 = list(map(''.join, zip(*[iter(hmackey)]*2)))
        
        # Format as 0x?? chars
        s1 = ''.join(map(lambda i: '0x' + i + ',', array1))
        s1 = '{' + s1[0:len(s1)-1] + '};\n\n'
        s1 = 'const unsigned char aes_key[] = ' + s1
        
        s2 = ''.join(map(lambda i: '0x' + i + ',', array2))
        s2 = '{' + s2[0:len(s2)-1] + '};\n\n'
        s2 = 'const unsigned char hmac_key[] = ' + s2
        
        fp.write('#ifndef SECRETS_H\n')
        fp.write('#define SECRETS_H\n')
        fp.write(s1)
        fp.write(s2)
        fp.write('\n#endif //SECRETS_H')


def copy_initial_firmware(binary_path):
    """
    Copy the initial firmware binary to the bootloader build directory
    Return:
        None
    """
    # Change into directory containing tools
    os.chdir(FILE_DIR)
    bootloader = FILE_DIR / '..' / 'bootloader'
    shutil.copy(binary_path, bootloader / 'src' / 'firmware.bin')


def make_bootloader():
    """
    Build the bootloader from source.

    Return:
        True if successful, False otherwise.
    """
    # Change into directory containing bootloader.
    bootloader = FILE_DIR / '..' / 'bootloader'
    os.chdir(bootloader)

    subprocess.call('make clean', shell=True)
    status = subprocess.call('make')

    # Return True if make returned 0, otherwise return False.
    return (status == 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Bootloader Build Tool')
    parser.add_argument("--initial-firmware", help="Path to the the firmware binary.", default=None)
    args = parser.parse_args()
    if args.initial_firmware is None:
        binary_path = FILE_DIR / '..' / 'firmware' / 'firmware' / 'gcc' / 'main.bin'
    else:
        binary_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(binary_path):
        raise FileNotFoundError(
            "ERROR: {} does not exist or is not a file. You may have to call \"make\" in the firmware directory.".format(binary_path))

    write_secret()
    copy_initial_firmware(binary_path)
    make_bootloader()