import string
from base64 import b64decode
import lzf
from Crypto.Cipher import AES

unpad = lambda s: s[: -ord(s[len(s) - 1 :])]


def decode_base64(
    encoded_string: bytes,
    custom_alphabet="Vhw4W3uB5OcY8qrp21NxbHs7ynSJFoPTEdAUtv9QagIDl6MR0KZkmjfeiCzGXL+/",
) -> bytes:
    newB64Table = str.maketrans(
        custom_alphabet,
        string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/",
    )
    new_str = str(encoded_string).translate(newB64Table)
    # Add '=' char at the end of the string if needed
    miss_padding = 4 - len(new_str) % 4
    if miss_padding:
        new_str += "=" * miss_padding
    return b64decode(new_str)


def decompress_lzf(buffer: bytes, size=100000000) -> bytearray:
    """
    Parameters:
      - buffer: input buffer of bytes
      - size: must be large enough to hold the decompressed buffer
    """
    return lzf.decompress(buffer, size)


def xor_buffer(buffer: bytes, key: int) -> bytes:
    return bytes([x ^ key for x in buffer])


def not_buffer_with_padding(buffer: bytes, size: int) -> bytes:
    """
    Parameters:
      - buffer: input buffer of bytes
      - size: the size of the output - can be larger than the size of the input buffer
    """
    outbuffer = []
    for x in range(0, size):
        if x < len(buffer[4:]):
            outbuffer.append(~buffer[4 + x] & 0xFF)
        else:
            outbuffer.append(~0x00 & 0xFF)
    return bytes(outbuffer)


def not_buffer(buffer: bytes):
    return bytes([(~x & 0xFF) for x in buffer])


def aesDecrypt(key, enc):
    enc = bytes(bytearray(enc))
    key = bytes(bytearray(key))
    cipher = AES.new(key, AES.MODE_CBC, key[0:16])
    return unpad(cipher.decrypt(enc))


def computeKey(client, server):
    key = []
    for x in range(0, 32):
        key.append(client[x] ^ server[x])
    return key


def computeSecondAESKey(xorkey):
    loop_condition = 0
    data = [
        0x0D,
        0x01,
        0x01,
        0x0B,
        0x05,
        0x00,
        0x30,
        0x6C,
        0x31,
        0x0B,
        0x30,
        0x09,
        0x06,
        0x03,
        0x55,
        0x04,
        0x06,
        0x13,
        0x02,
        0x55,
        0x53,
        0x31,
        0x15,
        0x30,
        0x13,
        0x06,
        0x03,
        0x55,
        0x04,
        0x0A,
        0x13,
        0x0C,
    ]
    aes_key = []

    for c in data:
        current_key = xorkey[loop_condition % 8]
        aes_key.append(c ^ current_key)
        loop_condition += 1
    return aes_key
