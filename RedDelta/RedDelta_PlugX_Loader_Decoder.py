
import pefile
import argparse
import textwrap

def loaderDecode(filename):

    with open(filename, "rb") as dat:
        data = dat.read()

    key = []

    for d in data:
        if d != 0x00:
            key.append(d)
        else:
            break

    klen = len(key)

    output = []
    loop_condition = 0
    for c in data[klen + 1:]:
        current_key = key[loop_condition % klen]
        output.append(c ^ current_key)
        loop_condition += 1

    with open("RedDelta_PlugX_Loader_Decoded.exe", "wb") as decoded:
        decoded.write(bytearray(output))

def getData(filename):
    raw = 0
    pe = pefile.PE(filename)

    try:
        for section in pe.sections:
            if '.data' in str(section.Name):
                data = section.PointerToRawData
    except OSError as e:
        print(e)
    except pefile.PEFormatError as e:
        print("[-] PEFormatError: %s" % e.value)
    return data

def configDecode(config):

    decoded=[]
    if config[0:7] != "########":
        key = [0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39]
        klen = len(key)

        loop_condition = 0
        for c in config:
            current_key = key[loop_condition % klen]
            decoded.append(c ^ current_key)
            loop_condition += 1
    else:
        decoded=config
    s = ""
    ConfigItems=[]
    for b in decoded:
        if b!=0x00:
            s+=chr(b)
        else:
            if len(s) >= 1:
                ConfigItems.append(s)
            s=""
    return ConfigItems

def main():
    logo = """
╦┌┐┌┌─┐┬┬┌─┌┬┐  ╔═╗┬─┐┌─┐┬ ┬┌─┐
║│││└─┐│├┴┐ │   ║ ╦├┬┘│ ││ │├─┘
╩┘└┘└─┘┴┴ ┴ ┴   ╚═╝┴└─└─┘└─┘┴  
    """
    banner = """
%s
RedDelta PlugX Payload Decode and Configuration Extract
----------------------------------------------------------------
This tool will decode the encoded PlugX Loader (xxx.dat) file. 
A attempt to decode the config will also be made.

The output will be saved as "RedDelta_PlugX_Loader_Decoded.exe"

To use, just pass the full path of the encoded PlugX loader file

Examples:
\t python RedDelta_PlugX_Loader_Decoder.py -f  <FULL PATH TO DOWNLOADED DAT FILE>
""" % (
        logo
    )

    # Checks to make sure that file is passed via command line
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner),
    )
    parser.add_argument("-f", "--file", help="PlugX Loader File")

    args = parser.parse_args()

    if args.file:
        try:
            loaderDecode(args.file)
            data = getData("RedDelta_PlugX_Loader_Decoded.exe")
            with open("RedDelta_PlugX_Loader_Decoded.exe", 'rb') as f:
                f.read(data)
                todecode = f.read(0x728)
            config=configDecode(todecode)
            print("Extracted Configuration Items")
            for c in config:
                print(c)
        except:
            print("Something didn't work right, ensure this is a PlugX Loader file and "
                  "that the correct arguments were passed")

if __name__ == "__main__":
    main()
