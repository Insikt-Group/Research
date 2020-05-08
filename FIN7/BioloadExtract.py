import pefile
import argparse
import textwrap

# Get RAW address of Reloc Section


def getReloc(filename):
    raw = 0
    pe = pefile.PE(filename)

    try:
        for section in pe.sections:
            if '.reloc' in str(section.Name):
                raw = section.PointerToRawData
    except OSError as e:
        print(e)
    except pefile.PEFormatError as e:
        print("[-] PEFormatError: %s" % e.value)
    return raw

# Find the starting place of the string to decode


def findStart(bin):
    found = False
    length = 0
    count = 0
    while found == False:
        if int(bin[count]) != 0:
            length += 1
        if length == 16:
            if 0x4E < count < 0x74:
                found = True
            length = 0
        count += 1
    return count

# Decode to get the Key


def getKey(bin, count):

    full = bytearray([0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74,
                      0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65])
    index = count-0x4D
    coded = bin[count:count+16]
    decoded = full[index:index+16]
    index = 0
    key = []
    for c in coded:
        for x in range(0, 255):
            if int(x ^ c) == int(decoded[index]):
                key.append(int(x))
        index += 1
    return key

# Decode File

# Decode payload and save as Bioload_Secondary_Payload.exe


def decodeFile(bin, key):
    loop_condition = 0
    out = open("Bioload_Secondary_Payload.exe", "wb")
    for b in bin:
        current_key = key[loop_condition % 16]
        if b == 0:
            dec = 0x00
            out.write(dec.to_bytes(1, 'big'))
        elif (b ^ current_key) == 0:
            dec = current_key
            out.write(dec.to_bytes(1, 'big'))
        else:
            dec = (b ^ current_key) & 0xfff
            out.write(dec.to_bytes(1, 'big'))
            loop_condition += 1
    out.close()


def main():
    logo = """
╦┌┐┌┌─┐┬┬┌─┌┬┐  ╔═╗┬─┐┌─┐┬ ┬┌─┐
║│││└─┐│├┴┐ │   ║ ╦├┬┘│ ││ │├─┘
╩┘└┘└─┘┴┴ ┴ ┴   ╚═╝┴└─└─┘└─┘┴  
    """
    banner = """
%s
BIOLOAD Embedded Payload Extract
----------------------------------------------------------------
This tool will extract and decode the embedded payload in BIOLOAD Files.
The output will be saved as "Bioload_Secondary_Payload.exe"

To use, just pass the full path of the BIOLOAD file

Examples:
\t python BioLoadExtract.py -f  <FULL PATH TO BIOLOAD FILE>
""" % (
        logo
    )

    # Checks to make sure that file is passed via command line
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner),
    )
    parser.add_argument("-f", "--file", help="BIOLOAD FILE")

    args = parser.parse_args()

    if args.file:
        try:
            raw = getReloc(args.file)
            cb_offset = raw + 0xe00
            with open(args.file, 'rb') as f:
                f.read(cb_offset)
                todecode = f.read()
            count = findStart(bytearray(todecode))
            key = getKey(todecode, count)
            decodeFile(todecode, key)
        except:
            print("Something didn't work right, ensure this is a Bioload file and that the correct arguments were passed")


if __name__ == "__main__":
    main()
