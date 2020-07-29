
import argparse
import textwrap
import lznt1

def decompress(filename):
    with open(filename,"rb") as toDecode:
        data=toDecode.read()
    return (lznt1.decompress(data))

def loaderDecode(filename):

    data = decompress(filename)

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

    with open("RedDelta_PlugX_Install_DAT_Decoded.exe", "wb") as decoded:
        decoded.write(bytearray(output))

def main():
    logo = """
╦┌┐┌┌─┐┬┬┌─┌┬┐  ╔═╗┬─┐┌─┐┬ ┬┌─┐
║│││└─┐│├┴┐ │   ║ ╦├┬┘│ ││ │├─┘
╩┘└┘└─┘┴┴ ┴ ┴   ╚═╝┴└─└─┘└─┘┴  
    """
    banner = """
%s
RedDelta PlugX Installation DAT File Decode
----------------------------------------------------------------
This tool will decompress and decode the Installation DAT file downloaded 
from a first stage C2(xxx.dat)

The output will be saved as "RedDelta_PlugX_Install_DAT_Decoded.exe"

To use, just pass the full path of the encoded PlugX loader file

Examples:
\t python RedDelta_PlugX_Install_DAT_Decoder.py -f  <FULL PATH TO DOWNLOADED DAT FILE>
""" % (
        logo
    )

    # Checks to make sure that file is passed via command line
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner),
    )
    parser.add_argument("-f", "--file", help="PlugX Install DAT File")

    args = parser.parse_args()

    if args.file:
        try:
            loaderDecode(args.file)
            print("File has been saved as, RedDelta_PlugX_Install_DAT_Decoded.exe")
        except:
            print("Something didn't work right, ensure this is a PlugX Install DAT file and "
                  "that the correct arguments were passed")

if __name__ == "__main__":
    main()
