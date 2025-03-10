#!/usr/bin/env python
"""
Firmware Bundle-and-Protect Tool

This tool receives the new firmware and encrypts it with AES128-GCM along with metadata,
creates frames and builds hmacs.
A blob of all of the data is created, which is sent to fw_update.py
"""
import argparse
import struct

from math import *

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from Crypto.Hash import HMAC, SHA256


def protect_firmware(infile, outfile, version, message):
    """
    Creates metadata, hashes, and encrypts firmware
    """
    
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()
        
    # Read aes key and hmac key from ./secret_build_output.txt
    with open("./secret_build_output.txt", 'rb') as f:
        aes_key = bytes.fromhex(f.readline().decode())
        hmackey = bytes.fromhex(f.readline().decode())
    
    
    # METADATA
    """
    This part of the blob creates the metadata of the entire (unencrypted) firmware
    """
    
    ##################################################################################################
    #                        Metadata                              #         Metadata Hash           #
    ##################################################################################################
    # 2b version / 2b len of firmaware / 2b len of release message # 32b hmac hash of 6b of metadata #
    ##################################################################################################
    
    firmware_size = len(firmware)
    # Pack version, firmware size, number of frames and release message length into 3 shorts
    metadata = struct.pack('<HHH', version, len(firmware), len(message))
    # Generate hmac hash for the metadata
    metadata_hash = HMAC.new(hmackey, metadata, digestmod=SHA256).digest()

    metadata_and_hash = metadata + metadata_hash
    
    
    # FIRMWARE ENCRYPTION
    """
    This encrypts the firmware and generates iv + hmac of the entire encrypted firmware
    """
    
    # Firmware Metadata
    firmware_data = b""
    # Generates 16-byte iv for aes-gcm encryption
    iv = get_random_bytes(16)
    # Creates aes-gcm cipher using the aes key in ./secret_build_output.txt
    gcm_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    # Encrypts entire firmware and generates 16-byte tag using aes128-gcm
    encrypted_firmware, tag = gcm_cipher.encrypt_and_digest(firmware)
    # Generates 32-byte HMAC-SHA256 hash of the entire firmware
    fw_hash_total = HMAC.new(hmackey, encrypted_firmware, digestmod=SHA256).digest()
    
    
    # FIRMWARE FRAMES
    """
    This part of the blob consists of pages and the metadata of each page, along with hmac hashes
    """
    
    ###############################################################################################
    #                                        ===LOOPED===                                         #
    ###############################################################################################
    #                 Firmware Metadata                #         Firmware Metadata Hash           #
    ###############################################################################################
    # 2b page index / 2b size of page / 2b version num #  32b hmac hash of 6b firmware metadata   #
    ###############################################################################################
    #                  Page/Firmware Data                       #          Page/Data Hash         #
    ###############################################################################################
    # 1024b chunk of the firmware (could be less if last chunk) #    32b hmac hash of page data   #
    ###############################################################################################
    
    ####################################################################
    #                      ===APPENDED AT END===                       # 
    ####################################################################
    #                        Firmware Total Hash                       #
    ####################################################################
    # 32b hmac hash of the entire encrypted firmware (generated above) #
    ####################################################################
    
    # Loops through entire encrypted firmware with chunks of max 1024
    for i in range(0, len(encrypted_firmware), 1024):
        # If the chunk of firmware is the full size of 1024
        if (i + 1024 < len(encrypted_firmware)):
            page = encrypted_firmware[i:i+1024]
        # If the chunk of firmware (last one) is less than 1024
        else:
            page = encrypted_firmware[i:len(encrypted_firmware)]
        # 2-byte short for the page index (to ensure pages are sent and received in correct order)
        page_index = struct.pack("<H", ceil(i/1024))
        # 2-byte short for the page length
        page_size = struct.pack("<H", len(page))
        # 2-byte short for the version number (an extra integrity check)
        version_number = struct.pack("<H", version)
        
        page_metadata = page_index + page_size + version_number
        
        # Generates a hmac hash of the respective page's metadata
        fw_metadata_hash = HMAC.new(hmackey, page_metadata, digestmod=SHA256).digest()
        # Generates a hmac hash of the paga data along with the page's metadata (the metadata is added to add another auth/integ check)
        fw_data_hash = HMAC.new(hmackey, page + page_metadata, digestmod=SHA256).digest()
        
        firmware_data += page_metadata + fw_metadata_hash + page + fw_data_hash
        
    # At the end of the loop, we append the hmac hash generated above of the entire encrypted firmware
    firmware_data += fw_hash_total
    
    
    # RELEASE MESSAGE
    """
    This part of the blob is the release message and its own hmac
    """
    
    #########################################################
    #        Release Message         # Release Message Hash #
    #########################################################
    #   (size determined above)bytes #     32b hmac hash    # 
    #########################################################
    
    # Encode the release message into bytes
    rmessage = message.encode()
    # Generate hmac hash of the release message
    rmessage_hash = HMAC.new(hmackey, rmessage, digestmod=SHA256).digest()
    
    release_message_data = rmessage + rmessage_hash
    
    
    # BIG MAC
    """
    The big mac is an hmac of the entire encrypted firmware, entire metadata, and release message
    This exists to be another authenticity/integrity check on top of the others
    """
    
    ##################################################################
    #                            BIG MAC                             #
    ##################################################################
    # 32b hmac hash of encrypted firmware, metadata, release message #
    ##################################################################
    
    big_data = encrypted_firmware + metadata + rmessage
    # Generates the hmac
    big_mac = HMAC.new(hmackey, big_data, digestmod=SHA256).digest()
    
    
    # BLOB
    """
    This is where the blob is created. All chunks from above are combined, back to back, with the AES-GCM iv and tag appended
    """
    firmware_blob = metadata_and_hash + bytes(firmware_data) + release_message_data + big_mac + iv + tag
    
    
    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)