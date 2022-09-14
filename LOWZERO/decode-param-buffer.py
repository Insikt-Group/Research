import argparse
import struct

from lowzerodev import *


def print_buffer(buff):
    num_of_16_rows = int(len(buff) / 0x10)
    print(
        "0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F"
    )
    print(
        "---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- ---- "
    )
    for j in range(0, num_of_16_rows):
        print(" ".join([f"{y:#0{4}x}" for y in buff[j * 0x10 : (j * 0x10) + 0x10]]))

    last_set = int(len(buff) % 0x10)
    if last_set > 0:
        print(
            " ".join(
                [
                    f"{y:#0{4}x}"
                    for y in buff[
                        num_of_16_rows * 0x10 : (num_of_16_rows * 0x10) + last_set
                    ]
                ]
            )
        )


def deobfuscate_config_bytes():

    buffer = bytes(
        [
            0x88,
            0x00,
            0x9B,
            0x00,
            0xE0,
            0xD9,
            0xFF,
            0xC7,
            0xBC,
            0xC6,
            0xBD,
            0xBD,
            0xCA,
            0xC7,
            0xCC,
            0xD2,
            0xC8,
            0xBC,
            0xCD,
            0xC9,
            0xD2,
            0xCB,
            0xC6,
            0xC6,
            0xCF,
            0xD2,
            0xBE,
            0xBE,
            0xC8,
            0xCC,
            0xD2,
            0xBA,
            0xC9,
            0xC9,
            0xB9,
            0xCA,
            0xC6,
            0xED,
            0xCB,
            0xBE,
            0xCA,
            0xBE,
            0xBB,
            0xCA,
            0xFF,
            0xFF,
            0xB2,
            0xFF,
            0x71,
            0x34,
            0x62,
            0x4D,
            0x71,
            0x6B,
            0x46,
            0x4D,
            0x71,
            0xDF,
            0xF8,
            0xE0,
            0x38,
            0x55,
            0x35,
            0x5A,
            0x77,
            0x78,
            0x57,
            0x4B,
            0x38,
            0x56,
            0x76,
            0x6B,
            0x6F,
            0x75,
            0x33,
            0x6D,
            0x53,
            0x73,
            0x38,
            0x36,
            0x6E,
            0x66,
            0x4B,
            0x52,
            0x79,
            0x39,
            0x33,
            0x6C,
            0x59,
            0x37,
            0x38,
            0x36,
            0xE0,
            0x4A,
            0x37,
            0x71,
            0x4D,
            0x59,
            0x73,
            0x71,
            0x52,
            0x4A,
            0x4E,
            0x43,
            0x64,
            0x53,
            0x66,
            0x33,
            0x36,
            0x79,
            0x73,
            0x76,
            0x7A,
            0x6E,
            0x73,
            0x32,
            0x4D,
            0x4A,
            0x39,
            0x48,
            0x6D,
            0x77,
            0x32,
            0x57,
            0x4F,
            0xFF,
            0xFF,
            0x1F,
            0xF0,
            0xFF,
            0xFE,
            0x9F,
            0x15,
            0x7F,
            0xFC,
            0xFC,
            0xCF,
            0x8A,
            0xFF,
            0xFF,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    )

    print("")
    print("Original Buffer")
    print_buffer(buffer)

    print("")
    size = struct.unpack("<H", buffer[0:2])[0]
    print(f"Encrypted Buffer Size: {hex(size)}")

    decypted_buffer = not_buffer_with_padding(buffer, size)

    print("")
    print("Decrypted  Buffer")
    print_buffer(decypted_buffer)

    out_buffer = decompress_lzf(decypted_buffer)

    print("")
    print("Decompressed Buffer")
    print_buffer(out_buffer)

    next_buffer = out_buffer[out_buffer[0] + 2 :]
    print("")
    print("Base64 Buffer Length + Encrypted Base64 Buffer")
    print_buffer(next_buffer)

    print("")
    print(f"Length of Base64 Value: {hex(next_buffer[0])}")

    print("")
    print("Base64 Value Decrypted (hex)")
    cnc_buffer = next_buffer[2 : next_buffer[0] + 1]
    cnc_buffer = not_buffer(cnc_buffer)
    print_buffer(cnc_buffer)

    print("")
    print("Base64 Value (str)")
    str = "".join([chr(x) for x in cnc_buffer])
    print(str)
    print("")

    cnc_info = decode_base64(str).split(b"\t")

    print("")
    print("Parsed Values")
    print(
        "--------------------------------------------------------------------------------------------------"
    )
    print(f"Campaign ID (mutex) Length: {hex(out_buffer[0])}")
    print(
        f'Campaign ID (mutex): {"".join([chr(x) for x in out_buffer[1:out_buffer[0]+2]])}'
    )

    if len(cnc_info) == 5:
        print(f"C2 Address: {cnc_info[0]}")
        print(f"C2 Port: {cnc_info[1]}")
        print(f"Fake SSL Cert Domain: {cnc_info[2]}")
        print(f"Switchcase Route: {cnc_info[3]}")


def deobfuscate_network_comms():
    # Client Random Bytes from TLS Handshake (PCAP)
    client_random_bytes = [
        0x61,
        0x0E,
        0xC8,
        0x8C,
        0xD9,
        0xD4,
        0x2A,
        0x84,
        0xD5,
        0x75,
        0xCE,
        0x43,
        0xD6,
        0xF8,
        0xED,
        0x30,
        0x74,
        0x2C,
        0x6A,
        0xAE,
        0x5B,
        0x99,
        0xFD,
        0xA8,
        0x94,
        0xB6,
        0x90,
        0x6D,
        0x06,
        0x5D,
        0xE9,
        0xBF,
    ]

    # Server Random Bytes from TLS Handshake (PCAP)
    server_random_bytes = [
        0x31,
        0x7F,
        0x55,
        0xD2,
        0x97,
        0x74,
        0xD6,
        0x4E,
        0x34,
        0x29,
        0xFC,
        0x2A,
        0x92,
        0xC4,
        0xAE,
        0x09,
        0xF8,
        0x77,
        0x5F,
        0xEA,
        0xE2,
        0x4F,
        0xC0,
        0xD3,
        0x1D,
        0x75,
        0x32,
        0xB3,
        0x4B,
        0x7A,
        0xB1,
        0x99,
    ]

    # TLS payload to decrypt, decode and decompress (PCAP) 
    data = [
        0x2B,
        0x64,
        0xB1,
        0xA4,
        0xFF,
        0x06,
        0x60,
        0x7B,
        0xBA,
        0x4E,
        0xA5,
        0x81,
        0x67,
        0x89,
        0x38,
        0x38,
        0x6D,
        0x1F,
        0xB6,
        0xA5,
        0x4E,
        0x00,
        0xC0,
        0x20,
        0x12,
        0xB6,
        0xD5,
        0xD2,
        0x13,
        0x1B,
        0xC4,
        0xCA,
        0x37,
        0xBB,
        0x99,
        0xF8,
        0xBB,
        0x7D,
        0xB9,
        0x60,
        0x09,
        0x80,
        0x00,
        0x8D,
        0x99,
        0xA4,
        0x78,
        0x6A,
        0xFB,
        0xB7,
        0x45,
        0xE3,
        0x07,
        0x37,
        0x54,
        0xE3,
        0x76,
        0x18,
        0x29,
        0xD9,
        0xCE,
        0x19,
        0x3F,
        0xA9,
        0x18,
        0x32,
        0xF8,
        0xB6,
        0x6A,
        0xA1,
        0x6D,
        0xF0,
        0xB7,
        0x83,
        0xDE,
        0xFE,
        0xF6,
        0x7C,
        0x9D,
        0x07,
    ]

    # First AES decrypt derives the key using the client and server random bytes from the TLS handshake
    aes_key = computeKey(client_random_bytes, server_random_bytes)
    print("\nThe first level AES key is:\n")
    print_buffer(aes_key)
    data = aesDecrypt(aes_key, data)
    print("\nThe first level decrypted data blob is:\n")
    print_buffer(data)

    # Second AES decrypt derives a key using a rolling xor key from the decrypted payload against hardcoded bytes
    secondStageLength = struct.unpack("<I", data[0:4])[0]
    data = data[4 : (4 + secondStageLength)]
    aes_key = computeSecondAESKey(data[0:8])
    print("\nThe second layer AES key is:\n")
    print_buffer(aes_key)
    data = aesDecrypt(aes_key, data[8:])
    print("\nThe second level decrypted data blob is:\n")
    print_buffer(data)
    if b"PK" in data:
        data = data[(data.index(b"PK")) :]
        commandNumber = data[2:6]
        commandRaw = struct.unpack("<H", data[6:8])[0]
        dataLength = struct.unpack("<I", data[8:12])[0]
        data = data[12 : (12 + dataLength)]

        bd64 = decode_base64("".join([chr(x) for x in data]))

        buffer = xor_buffer(bd64, 0x2B)

    if len(buffer) > 0x10:
        buffer = decompress_lzf(bytes(buffer[4:]))

    print(f"\nThe command is: {(commandRaw)}")
    print(f"The command data is: {buffer}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        action="store_true",
        help="Run the code to show decrypting the config",
    )
    parser.add_argument(
        "--comms", action="store_true", help="Run the code to show decrypting the comms"
    )
    args = parser.parse_args()
    if args.config:
        print("")
        print("[!] Extract Config From Bytes [!]")
        print("")
        deobfuscate_config_bytes()
    if args.comms:
        print("[!] Decrypting Comms [!]")
        print("")
        deobfuscate_network_comms()
