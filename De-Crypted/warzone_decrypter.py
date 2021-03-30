import argparse
import logging
import re
import pefile
from arc4 import ARC4
from struct import unpack

##### Helpful String stuff inspired by stringsifter (https://github.com/fireeye/stringsifter/blob/master/stringsifter/flarestrings.py)
ASCII_BYTE = b" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
MIN_LEN = 4

def yesno(i):
    if i == b'\x01':
        return "Yes"
    else:
        return "No"

def extractConfig(confgBlock):
    config = {
        "Hostname":"",
        "Port" : "",
        "Random String": "",
        "Install":"",
        "Use ADS Install + Startup":"",
        "Install Name": "",
        "Startup": "",
        "Startup Name":"",
        "Offline Logs":"",
        "Persistance":"",
        "Enable UAC":"",
        "Bypass Windows Defender": ""
    }

    hostLength = unpack("<I", confgBlock[0:4])[0]
    currentOffset = 4
    config["Hostname"] = confgBlock[4:hostLength + currentOffset].decode("utf-16-le")
    currentOffset += hostLength
    config["Port"] = unpack("<H", confgBlock[currentOffset:currentOffset + 2])[0]
    currentOffset += 2 + 6
    config["Install"] = yesno((confgBlock[currentOffset:currentOffset + 1]))
    currentOffset += 1
    if config["Install"] == "Yes":
        Install_Length = unpack("<I", confgBlock[currentOffset:currentOffset + 4])[0]
        currentOffset += 4
        config["Install Name"] = confgBlock[currentOffset:currentOffset + Install_Length].decode("utf-16-le")
        currentOffset += Install_Length
    config["Startup"] = yesno((confgBlock[currentOffset:currentOffset + 1]))
    currentOffset += 1
    if config["Startup"] == "Yes":
        Startup_Length = unpack("<I", confgBlock[currentOffset:currentOffset + 4])[0]
        currentOffset += 4
        config["Startup Name"] = confgBlock[currentOffset:currentOffset + Startup_Length].decode("utf-16-le")
        currentOffset += Startup_Length
    currentOffset = confgBlock.index(b'\x88\x13\x00\x00')
    currentOffset += 4
    config["Offline Logs"] = yesno((confgBlock[currentOffset:currentOffset + 1]))
    currentOffset += 1
    config["Persistance"] = yesno((confgBlock[currentOffset:currentOffset + 1]))
    currentOffset += 1
    config["Enable UAC"] = yesno((confgBlock[currentOffset:currentOffset + 1]))
    currentOffset += 1
    config["Bypass Windows Defender"] = yesno((confgBlock[currentOffset:currentOffset + 1]))
    currentOffset += 1
    config["Use ADS Install + Startup"] = yesno((confgBlock[currentOffset:currentOffset + 1]))
    currentOffset += 1
    randomLength = unpack("<I", confgBlock[currentOffset:currentOffset + 4])[0]
    currentOffset += 4
    config["Random String"] = confgBlock[currentOffset:currentOffset + randomLength].decode("utf-16-le")

    return config

def getBSS(filename):
    raw = 0
    size = 0
    pe = pefile.PE(filename)
    try:
        for section in pe.sections:
            if '.bss' in str(section.Name):
                raw = section.PointerToRawData
                size = section.SizeOfRawData
    except OSError as e:
        print(e)
    except pefile.PEFormatError as e:
        print("[-] PEFormatError: %s" % e.value)
    return raw,size

def getEncodedData(filename,dataRaw,size):

    key=""
    cipher=""

    with open(filename, 'rb') as f:
        f.read(dataRaw)
        keysize = unpack("<I", f.read(4))[0]
        key = f.read(keysize)
        cipher = f.read((size - 4 - keysize))
    return key,cipher





##### Packed File Extraction ###########

VERSION_DATA = {
    "3_1x": {
        # "start": b'\xCC\xCC\xCC\xCC\xF6\xF6\xF6\xF6',
        "start": b'\x8f\x00\x00\x00\x34\x00\x00\x00',
        "end": b'\x00' * 8,
        "reverse": True,
        "compression_size": 4,
        "xorkey": [
            0x98, 0xcb, 0x81, 0x1c, 0xd3, 0x4c, 0xed, 0x7, 0xd8, 0x86, 0x9b, 0x9b, 0x31, 0xd0,
            0x83, 0xdf, 0xcd, 0x98, 0x98, 0xd1, 0x99, 0x4e, 0xde, 0x82, 0x58, 0x1d, 0x1a, 0xf8,
            0xac, 0x8e, 0xc0, 0x2f, 0xe8, 0x99, 0xdc, 0xd2, 0xfe, 0x4a, 0x13, 0x76, 0x47, 0x2,
            0x3a, 0x4a, 0xdc, 0x32, 0xa7, 0x95, 0x9b, 0x70, 0xfb, 0xbb, 0xe7, 0xf2, 0x4, 0x23,
            0xe1, 0xe4, 0xba, 0x78, 0xcc, 0x75, 0xc5, 0x11, 0x33, 0xcd, 0x4d, 0xb6, 0xf6, 0xe0,
            0xfd, 0x70, 0x89, 0xa, 0x7c, 0xf3, 0xd7, 0x70, 0xa, 0xe2, 0x83, 0x97, 0x74, 0xf0,
            0xed, 0x4b, 0x2b, 0xfe, 0x3b, 0x4a, 0x59, 0xe4, 0x28, 0xe8, 0x50, 0x1, 0xce, 0x49,
            0x9, 0x33
        ],
    },
    "3_11": {
        "start": b'\x8f' * 4 + b'\x34' * 4,
        "end": b'\x00' * 8,
        "reverse": True,
        "compression_size": 4,
        "xorkey": [
            0x98, 0xcb, 0x81, 0x1c, 0xd3, 0x4c, 0xed, 0x7, 0xd8, 0x86, 0x9b, 0x9b, 0x31, 0xd0,
            0x83, 0xdf, 0xcd, 0x98, 0x98, 0xd1, 0x99, 0x4e, 0xde, 0x82, 0x58, 0x1d, 0x1a, 0xf8,
            0xac, 0x8e, 0xc0, 0x2f, 0xe8, 0x99, 0xdc, 0xd2, 0xfe, 0x4a, 0x13, 0x76, 0x47, 0x2,
            0x3a, 0x4a, 0xdc, 0x32, 0xa7, 0x95, 0x9b, 0x70, 0xfb, 0xbb, 0xe7, 0xf2, 0x4, 0x23,
            0xe1, 0xe4, 0xba, 0x78, 0xcc, 0x75, 0xc5, 0x11, 0x33, 0xcd, 0x4d, 0xb6, 0xf6, 0xe0,
            0xfd, 0x70, 0x89, 0xa, 0x7c, 0xf3, 0xd7, 0x70, 0xa, 0xe2, 0x83, 0x97, 0x74, 0xf0,
            0xed, 0x4b, 0x2b, 0xfe, 0x3b, 0x4a, 0x59, 0xe4, 0x28, 0xe8, 0x50, 0x1, 0xce, 0x49,
            0x9, 0x33
        ],
    },
    "3_09": {
        "start": b'\x8f\x00\x00\x00\x34\x00\x00\x00',
        "end": b'\x00' * 8,
        "reverse": True,
        "compression_size": 4,
        "xorkey": [
            0x98, 0xCB, 0x81, 0x1C, 0xD3, 0x4C, 0xED, 0x07, 0xD8, 0x86, 0x9B, 0x9B, 0x31, 0xD0, 0x83, 0xDF,
            0xCD, 0x98, 0x98, 0xD1, 0x99, 0x4E, 0xDE, 0x82, 0x58, 0x1D, 0x1A, 0xF8, 0xAC, 0x8E, 0xC0, 0x2F,
            0xE8, 0x99, 0xDC, 0xD2, 0xFE, 0x4A, 0x13, 0x76, 0x47, 0x02, 0x3A, 0x4A, 0xDC, 0x32, 0xA7, 0x95,
            0x9B, 0x70, 0xFB, 0xBB, 0xE7, 0xF2, 0x04, 0x23, 0xE1, 0xE4, 0xBA, 0x78, 0xCC, 0x75, 0xC5, 0x11,
            0x33, 0xCD, 0x4D, 0xB6, 0xF6, 0xE0, 0xFD, 0x70, 0x89, 0x0A, 0x7C, 0xF3, 0xD7, 0x70, 0x0A, 0xE2,
            0x83, 0x97, 0x74, 0xF0, 0xED, 0x4B, 0x2B, 0xFE, 0x3B, 0x4A, 0x59, 0xE4, 0x28, 0xE8, 0x50, 0x01,
            0xCE, 0x49, 0x09, 0x33
        ]
    },
    "3_qq": {
        "start": b'\x12\x00\x00\x00\xd1\x00\x00\x00',
        "end": b'\x00' * 8,
        "reverse": True,
        "compression_size": 4,
        "xorkey": [
            0x98, 0xCB, 0x81, 0x1C, 0xD3, 0x4C, 0xED, 0x07, 0xD8, 0x86, 0x9B, 0x9B, 0x31, 0xD0, 0x83, 0xDF,
            0xCD, 0x98, 0x98, 0xD1, 0x99, 0x4E, 0xDE, 0x82, 0x58, 0x1D, 0x1A, 0xF8, 0xAC, 0x8E, 0xC0, 0x2F,
            0xE8, 0x99, 0xDC, 0xD2, 0xFE, 0x4A, 0x13, 0x76, 0x47, 0x02, 0x3A, 0x4A, 0xDC, 0x32, 0xA7, 0x95,
            0x9B, 0x70, 0xFB, 0xBB, 0xE7, 0xF2, 0x04, 0x23, 0xE1, 0xE4, 0xBA, 0x78, 0xCC, 0x75, 0xC5, 0x11,
            0x33, 0xCD, 0x4D, 0xB6, 0xF6, 0xE0, 0xFD, 0x70, 0x89, 0x0A, 0x7C, 0xF3, 0xD7, 0x70, 0x0A, 0xE2,
            0x83, 0x97, 0x74, 0xF0, 0xED, 0x4B, 0x2B, 0xFE, 0x3B, 0x4A, 0x59, 0xE4, 0x28, 0xE8, 0x50, 0x01,
            0xCE, 0x49, 0x09, 0x33
        ]
    },
    "3_10q": {
        "start": b'\x88' + b'\x00' * 7 + b'\xe6' + b'\x00' * 7,
        "end": b'\x00' * 16,
        "reverse": True,
        "compression_size": 8,
        "xorkey": [
            0x9F, 0x19, 0x46, 0x7B, 0xB3, 0x22, 0x12, 0x7F, 0x9F, 0x3B, 0x08, 0x20, 0xB7, 0xF2, 0x98, 0xFE,
            0x28, 0xA9, 0xFA, 0x65, 0x4C, 0xC0, 0xCB, 0x59, 0x69, 0x3B, 0xEE, 0xAC, 0x3C, 0x7D, 0x97, 0x2F,
            0xC3, 0x25, 0x65, 0xEA, 0x4E, 0xF4, 0x63, 0x1D, 0x5E, 0xAB, 0x60, 0x6A, 0x6B, 0x1A, 0xED, 0x21,
            0xE7, 0x31, 0xF8, 0x74, 0x9E, 0x55, 0x24, 0xD0, 0x23, 0x52, 0xAF, 0x2B, 0x00, 0x58, 0x9C, 0xFF,
            0x9F, 0x76, 0xC6, 0x8F, 0x71, 0x49, 0xB5, 0xA9, 0x35, 0x82, 0x62, 0x57, 0x51, 0x9A, 0xCF, 0xBA,
            0x4D, 0x7F, 0xF7, 0x99, 0xAC, 0x47, 0x68, 0x47, 0x5F, 0x5B, 0x4A, 0x7A, 0x31, 0x3D, 0x8F, 0xEE,
            0xBC, 0x11, 0xA4, 0xE0
        ]
    }
}


def extract_data(pe_data, start_bytes, end_bytes, reverse=False):
    """

    Args:
        pe_data: byte string of the whole pe file
        start_bytes: byte string pattern to match for start
        end_bytes: byte string pattern to match for end
        reverse: bool whether to search backwards or forwards
    """
    if reverse:
        pe_data = pe_data[::-1]

    s_index = pe_data.find(start_bytes)
    if s_index == -1:
        raise Exception(f"Couldn't find byte pattern: {str(start_bytes)}")

    search = pe_data[s_index:]

    e_index = search.find(end_bytes)
    if e_index == -1:
        raise Exception(f"Couldn't find byte pattern: {str(end_bytes)}")

    return search[:e_index]


def compress_and_not(data, compression=4):
    """

    Args:
        data: data to compress and not
    """
    ret_data = []
    for b in data[::compression]:
        # bitwise not and only take the first byte (lowest entry in little endian form)
        ret_data.append(~b & 0xff)

    return ret_data


def rolling_xor_decrypt(data, key):
    ret_data = []

    for i, b in enumerate(data):
        ret_data.append(b ^ key[i % len(key)])

    return ret_data


def main():
    parser = argparse.ArgumentParser(description='Warzone unpacker')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of Warzone file to unpack')
    parser.add_argument('-o', '--ofile', action='store', dest='ofile',
                        required=True, help='Path to save extracted mz files')
    parser.add_argument('-v', '--debug', action='store_true', help='Add in debug logging')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    with open(args.file, "rb") as f:
        pe_data = f.read()

    # choose version
    for ver in VERSION_DATA.keys():
        try:
            sbytes = VERSION_DATA[ver]['start']
            ebytes = VERSION_DATA[ver]['end']
            reverse = VERSION_DATA[ver]['reverse']
            key = VERSION_DATA[ver]['xorkey']
            compression = VERSION_DATA[ver]['compression_size']

            # Snag start of encrypted data
            data = extract_data(pe_data, sbytes, ebytes, reverse=reverse)

            logging.debug(f"Extracted {len(data)} bytes")
            logging.debug(f"First 0x10 bytes:")
            logging.debug(data[:0x10])

            # Compress and apply not
            data = compress_and_not(data, compression=compression)
            logging.debug(f"Compressed to {len(data)} bytes")
            logging.debug(f"First 0x10 bytes:")
            logging.debug([hex(x) for x in data[:0x10]])

            # Use the right xor key
            data = rolling_xor_decrypt(data, key)
            logging.debug(f"Decrypted to {len(data)} bytes")
            logging.debug(f"First 0x10 bytes:")
            logging.debug([hex(x) for x in data[:0x10]])

            # Check we got it right
            # Shellcode starts with a jump
            if data[0] != 0xe8:
                logging.debug(f"Didn't find the shellcode jump!")

            data = b''.join([x.to_bytes(1, 'little') for x in data])
            logging.debug(f"Data in bytestr: {data[:0x10]}")
            mz = data.find(b'MZ')
            if mz != -1 and args.ofile:
                logging.debug(f"MZ found at {hex(mz)}")
                with open(f"{args.ofile}_pefile", "wb") as f:
                    f.write(data[mz:])

            # Check Warzone String
            wz_string = data.find(b'warzone160')
            if wz_string != -1:
                logging.info(f"{args.file}: Warzone string found at {hex(wz_string)}")
                # Writing Out Shellcode File
                if args.ofile:
                    with open(args.ofile, "wb") as f:
                        f.write(data)

                try:
                    logging.info(f"Trying to Decrypt Config")
                    file="%s_pefile" % (args.ofile)
                    dataRaw, sectionSize = getBSS(file)
                    key, cipher = getEncodedData(file, dataRaw,sectionSize)
                    arc4 = ARC4(key)
                    configblock = (arc4.decrypt(cipher))
                    config = extractConfig(configblock)
                    logging.info(f"\nDecrypted Config")
                    for k,v in config.items():
                        logging.info(f"{k}: {v}")

                except:
                    logging.exeception(f"Failed to decrypt config")


                return
        except Exception as e:
            logging.debug(f"Version {ver} failed: {e}")

    logging.info(f"{args.file}: No Warzone string found")


if __name__ == "__main__":
    main()
