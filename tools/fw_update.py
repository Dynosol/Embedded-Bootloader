#!/usr/bin/env python
"""
Firmware Updater Tool

A frame consists of six sections:
1. 2 bytes for the index of the frame
2. 2 bytes for the size of the frame
3. 2 bytes for the version number
4. 32 bytes for an hmac hash of the above metadata
5. Max 1024 bytes for the encrypted firmware data
6. 32 bytes for an hmac hash of the above encrypted firmware data

[ 0x02 ][ 0x02 ][ 0x02 ] [ 0x20 ][ ??? ][ 0x20 ]
-----------------------------------------------
| Index | Size | Version | Hash | Data | Hash |
-----------------------------------------------

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero

Before and after the frames are sent, supplementary bytes containing metadata,
decryption tools, and hashes are sent.
"""

import argparse
import struct
import time

from tqdm import tqdm
import os,binascii
import random as r

from math import *

from serial import Serial

# An OK response from the bootloader is received as a null byte
RESP_OK = b'\x00'

# Metadata size of firmware is 6 bytes
FW_MSIZE = 6
# (max) pagesize is 1024 bytes
PG_SIZE = 1024
# Metadata size of frame is 6 bytes
FR_MSIZE = 6
# Hmac hash size is constant, 32 bytes
HMAC_SIZE = 32
# Tag and IV for aes-gcm enc/dec are both 16 bytes
TAG_SIZE = 16
IV_SIZE = 16


def send_data(ser, data, length, debug=False):
    """
    This function is a framework for sending data to the bootloader
    Return:
        Input (the blob) minus what was just sent over serial
    """
    
    # Write data to UART
    ser.write(data[:length])
    
    # Wait for an OK from the bootloader
    resp = ser.read()  

    time.sleep(0.1)

    # If the bootloader responded with anything other than an OK message
    if resp != RESP_OK:
        # Return the error
        raise RuntimeError(f"ERROR: Bootloader responded with {format(repr(resp))}")
    
    return data[length:]


def main(ser, infile, debug):
    """
    Sends frames, metadata, hashes, etc. to bootloader
    """
    
    # Opened serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    
    # Read blob that was sent from fw_protect.py
    with open(infile, 'rb') as fp:
        firmware_blob = fp.read()
    
    # Receive size of the entire unencrypted firmware
    FIRMWARE_SIZE, = struct.unpack("<H", firmware_blob[2:4])
    # Receive size of release message
    RELEASE_MESSAGE_SIZE, = struct.unpack("<H", firmware_blob[4:6])
    # A ceiling function to calculate the total number of pages sent over from fw_protect
    PAGE_NUMBER = ceil(FIRMWARE_SIZE/PG_SIZE) 
    
    # Setting the bootloader to update mode and wait until it is ready
    ser.write(b'U')
    while ser.read(1).decode() != 'U':
        pass
      
    # Send firmware metadata and HMAC over serial
    firmware_blob = send_data(ser, firmware_blob, FW_MSIZE + HMAC_SIZE, debug=debug)
    
    # Loop that sends each frame, ends automatically when last frame is sent
    for i in tqdm(range(PAGE_NUMBER), unit="pages"):
        # Receive the index of the frame
        frame_index, = struct.unpack("<H", firmware_blob[:2])
        # Receive the size of the page
        FR_OUT, = struct.unpack("<H", firmware_blob[2:4])
        
        # Checks if order of received frames aligns with the indexes within the metadata of each frame
        if frame_index == i:
            firmware_blob = send_data(ser, firmware_blob, FR_MSIZE + FR_OUT + HMAC_SIZE * 2, debug=debug)
        else:
            raise RuntimeError(f"ERROR: Frame index incorrect at {i}, data said {frame_index}") 
        
        # Loading bar text
        print("", end='\r')
    # Reset text formatting to default
    print("\033[0m")
    
    # Send hmac hash of the entire encrypted firmware
    firmware_blob = send_data(ser, firmware_blob, HMAC_SIZE, debug=debug)
    
    # Send release message along with its hash
    firmware_blob = send_data(ser, firmware_blob, RELEASE_MESSAGE_SIZE + HMAC_SIZE, debug=debug)
    
    # Send big mac
    firmware_blob = send_data(ser, firmware_blob, HMAC_SIZE, debug=debug)
    
    # Send IV and tag for aes-gcm decryption
    firmware_blob = send_data(ser, firmware_blob, IV_SIZE + TAG_SIZE, debug=debug)
    
    # Send a zero length payload to tell the bootlader to finish writing its page.
    ser.write(struct.pack('>H', 0x0000))

    return ser
    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')

    parser.add_argument("--port", help="Serial port to send update over.",required=True)
    parser.add_argument("--firmware", help="Path to firmware image to load.",required=True)
    parser.add_argument("--debug", help="Enable debugging messages.",action='store_true')
    args = parser.parse_args()

    os.system('clear')
    
    # Prints ascii art and introduction (and warning....)
    print("\033[0m\033[1;94m")
    print("▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄")
    print("█▀▄█▀▄▀█▄▀███░▄▄█▄░▄█░▄▄▀█░██░█▀▄▀█▄░▄███░▄▄▀█░██░███░███▄██░▄▄▄█░████▄░▄█░▄▄▀██▄██░▄▄▀█░▄▄▄█")
    print("█░██░█▀██░███▄▄▀██░██░▀▀▄█░██░█░█▀██░████░▄▄▀█░▀▀░███░███░▄█░█▄▀█░▄▄░██░██░██░██░▄█░██░█░█▄▀█")
    print("█▄▀██▄██▀▄███▄▄▄██▄██▄█▄▄██▄▄▄██▄███▄████▄▄▄▄█▀▀▀▄███▄▄█▄▄▄█▄▄▄▄█▄██▄██▄██▄██▄█▄▄▄█▄██▄█▄▄▄▄█")
    print("▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀")
    
    print('\033[0m\033[34mThis is the struct by_lightning{}; update software!\n')
    print('COPYRIGHT © 2021 struct by_lightning{};')
    print('All rights reserved.\n\n\033[1;92m')
    print('Updating bootloader...')
    ser = Serial(args.port, baudrate=115200, timeout=2)
    main(ser=ser, infile=args.firmware, debug=args.debug)
    print("\n\033[1;91mHack us and you will suffer\n\033[0m")
    
    time.sleep(2)
    
    # Lightning bolt spinning animation
    
    os.system('clear')
    
    bolts = [
            ("                      :LMW            \n"+  
            "                  =ld#@@@!            \n"+  
            "                 v@@@@@@M             \n"+  
            "                `#@@@@@@_             \n"+  
            "                l@@@@@@s              \n"+  
            "               '#@@@@@#'_v`           \n"+  
            "               I@@@@@@#B#^            \n"+  
            "              -@@B@@@@@B'             \n"+
            "              :|-*@@@@$.              \n"+  
            "                 Q@@@5`               \n"+  
            "                v@@@V                 \n"+  
            "               `#@#*                  \n"+  
            "               u@#:                   \n"+  
            "              .#8-                    \n"+  
            "              sO.                     \n"+  
            "             ,8I                      \n"+  
            "                                      \n"),
    
            ("                     *]!`             \n"+  
            "                   _Z###B`            \n"+  
            "                 `cB####M             \n"+  
            "                 8######r             \n"+  
            "                !######B`             \n"+  
            "                l######e              \n"+  
            "                E#####@gI_            \n"+  
            "               _#####@@@d             \n"+  
            "               v#@##@@@Q`             \n"+  
            "               !}###@@#_              \n"+  
            "                ^##@@@*               \n"+  
            "                j#@@@y                \n"+  
            "                Q#@@d                 \n"+  
            "               =#@@#`                 \n"+  
            "               y@@@~``                \n"+  
            "               B@#s,                  \n"+  
            "               ,=(                    \n"+  
            "                                      \n"),
            
            ("                 lcccc}               \n"+  
            "                 B####B               \n"+  
            "                 Q####Q               \n"+  
            "                 8####8               \n"+  
            "                 $####$               \n"+  
            "                 E####E               \n"+  
            "                 B@@@@B               \n"+  
            "                 B@@@@B               \n"+  
            "                 Q@@@@Q               \n"+  
            "                 D@@@@D               \n"+  
            "                 b@@@@b               \n"+  
            "                 3@@@@K               \n"+  
            "                 k@@@@k               \n"+  
            "                 l@@@@l               \n"+  
            "                 i@@@@i               \n"+  
            "                 r####r               \n"+  
            "                 rGHGHr               \n"+  
            "                                      \n"),
        
            ("                ''(=                   \n"  
            "              `gQQ@K.                 \n"  
            "               KQQ#@#Y                \n"  
            "               *QQB@@@O               \n"  
            "               `QQQ@@@@.              \n"  
            "                mQQ#@@@v              \n"  
            "              -u6##B@@@5              \n"  
            "               H##@@@@@#`             \n"  
            "               `8##@@@@@>             \n"  
            "                :B##@@#v,             \n"  
            "                 r##@@@,              \n"  
            "                  w##@@}              \n"  
            "                   9##@0              \n"  
            "                   -Q##@.             \n"  
            "                   `~##@x             \n"  
            "                    _XB#O`            \n"  
            "                                      \n"  
            "                                      \n"),
        
            ("                                      \n"  
            "              jGv_                    \n"  
            "              :@@@#5x,                \n"  
            "               P@@@@@@*               \n"  
            "               -@@@@@@Q               \n"  
            "                m@@@@@@x              \n"  
            "             `*--@@@@@@#              \n"  
            "              ^#Q#@@@@@@x             \n"  
            "               'B@@@@@B@@-            \n"  
            "                -g@@@@~.r_            \n"  
            "                 `M@@@$               \n"  
            "                   y@@@r              \n"  
            "                    \@@Q              \n"  
            "                     =#@r             \n"  
            "                      _QB`            \n"  
            "                      `.0l`           \n"  
            "                                      \n"  
            "                                      \n"),
            
            ("               '                      \n" 
            "               s#0jr-                 \n" 
            "               <@@@@@#k               \n" 
            "                #@@@@@@`              \n" 
            "                3@@@@@@v              \n" 
            "               :}@@@@@@E              \n" 
            "               l#@@@@@@@,             \n" 
            "                g@@@@@@@V             \n" 
            "                ,@@@@@#r~             \n" 
            "                 }@@@@@-              \n" 
            "                  Q@@@@}              \n" 
            "                  :@@@@g              \n" 
            "                   y@@@@:             \n" 
            "                  ``Q@@@k             \n" 
            "                    *@@@B`            \n" 
            "                     Q@@@'            \n" 
            "                                      \n"
            "                                      \n"),
        
            ("                 lcccc}               \n"  
            "                 *cccc~               \n"  
            "                 Q@@@@D               \n"  
            "                 B@@@@8               \n"  
            "                 #@@@@Q               \n"  
            "                 #@@@@B               \n"  
            "                 @@@@@#               \n"  
            "                 @@@@@#               \n"  
            "                 #@@@@B               \n"  
            "                 B@@@@8               \n"  
            "                 #@@@@Q               \n"  
            "                 #@@@@B               \n"  
            "                 @@@@@#               \n"  
            "                 @@@@@#               \n"  
            "                `@@@@@@`              \n"  
            "                '@@@@@@`              \n"  
            "                 rGHGHr               \n"
            "                                      \n"),
        
            ("                        '             \n"  
            "                   _)yZQl             \n"  
            "                 h#@#BQB!             \n"  
            "                _@@@BBQ$              \n"  
            "                y@@#BQQV              \n"  
            "                B@@#BQBv_             \n"  
            "               ;@@@BBB#Qx             \n"  
            "               P@@#B#BBZ              \n"  
            "               (L@@@#BQ_              \n"  
            "                !@@@BB}               \n"  
            "                X@@@B6                \n"  
            "                #@@#Q:                \n"  
            "               ^@@@Bl                 \n"  
            "               W@@@6`                 \n"  
            "              '@@@#!                  \n"  
            "               @@@0                   \n"  
            "                                      \n"
            "                                      \n")
            ]
    
    for i in range(5):
        print("\033[33m")
        for j in range(8):
            print(bolts[j])
            time.sleep(0.2)
            os.system('clear')
            
    print("\033[0;103m")