import sys
import pefile
import re
import yara
import string

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def AES_decrypt(encrypted_file, decrypted_file, key):
    file_in = open(encrypted_file, 'rb')
    iv = file_in.read(16)
    ciphered_data = file_in.read()
    file_in.close()

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    original_data = unpad(cipher.decrypt(ciphered_data), AES.block_size)

    file_out = open(decrypted_file, 'wb')
    file_out.write(original_data)
    file_out.close()


if __name__ == "__main__":
    input_file = sys.argv[1]
    print("Shozab encrypted sample filename:" + input_file)

    # Load PE file
    pe = pefile.PE(input_file)

    # Use a YARA rule to locate the function call/parameter that contains the address of the encrypted resource string
    print("Identifying the encrypted malware resource name in memory ... ")
    rules = yara.compile(
        source='rule loading_resource_name { strings: $STR1 = { 68 ?? ?? ?? ?? 6a 0a 8b 0d 34 56 87 00 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f0 89 b3 dc 03 00 00 6a 00 6a 00 8b c6 } condition: $STR1 }')
    matches = rules.match(input_file)
    matching_address = matches[0].strings[0][0] + 0xc01
    resource_address = int.from_bytes(pe.get_memory_mapped_image()[matching_address:matching_address + 4], 'little')
    resource_address = resource_address - pe.OPTIONAL_HEADER.ImageBase

    # Pull the resource name out of memory and clean it up
    print("Resource name in binary at address:" + hex(resource_address))
    resource_name = pe.get_memory_mapped_image()[resource_address:resource_address + 16].decode('utf-16').upper()
    resource_name_ascii = ""
    for character in resource_name:
        if (character.isascii()) & (ord(character) != 0):
            resource_name_ascii += character
    resource_name = resource_name_ascii
    print("Resource name:" + resource_name)

    # Read in the file and search for ASCII characters encoded as UTF-16LE
    File = open(input_file, 'rb')
    file_data = File.read()
    File.close()
    pattern = re.compile(b'(?:[\x20-\x7E][\x00]){3,}')
    words = [w.decode('utf-16le') for w in pattern.findall(file_data)]

    # Run a regex over all UTF-16 strings in the binary to identify the key (32 characters with values 0-9)
    print("Extracting the AES key for the encrypted malware resource")
    extracted_key = ""
    for w in words:
        m = re.search(r'\b[0-9]{32}\b', w)
        if m != None:
            extracted_key = m.group(0)

    if extracted_key == "":
        print("Couldn't identify key... quitting")
        quit()
    print("Extracted AES key:" + extracted_key)

    found_resource = 0
    resource_file = ""

    # Extract the resource from the PE file based on the name we pulled from memory
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if entry.name.__str__() == resource_name:
                print("Found resource -- extracting ...")
                found_resource = 1
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                resource_file = input_file + ".rsrc"
                file_out = open(resource_file, 'wb')
                file_out.write(pe.get_memory_mapped_image()[offset:offset + size])
                file_out.close()

    if found_resource == 0:
        print("Couldn't find resource ... aborting")
        quit()

    # Decrypt the AES encrypted resource using the key, first 16 bytes of file are the IV
    print("Decrypting ....")
    output_file = resource_file + ".dec"
    key = bytes(extracted_key, 'utf-8')
    AES_decrypt(resource_file, output_file, key)

    # Test that the resulting file is another PE
    try:
        pe2 = pefile.PE(output_file)
        print("Decrypted file is a PE file")
    except pefile.PEFormatError as e:
        print("Decrypted file is not a PE file")
