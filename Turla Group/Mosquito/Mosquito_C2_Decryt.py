import urllib.parse,base64,argparse,textwrap
from struct import *

def bbs(start,mod):
    n=2
    png=0
    while(n<10):
        if start & 1:
            t=1<<(n-2)
            png=png | t
        if start & 8:
            t = 1 << (n - 1)
            png = png | t
        if start &0x20:
            t=1 << n
            png=png | t
        if start &0x4:
            #c=edi+1
            t=1 << (n +1)
            png= png | t
        q=start*start
        start=q%mod
        n+=4
    return png,start

def decodeString(toDecode):
    parsed={}
    mod = 0x7DFDC101
    urldecoded = urllib.parse.unquote_plus(toDecode)
    b64Decoded = base64.b64decode(urldecoded)

    start = unpack("<I", b64Decoded[0:4])[0]
    parsed["Start"]=start

    getstringDecode = []
    for b in b64Decoded[4:]:
        bl, start = bbs(start, mod)
        getstringDecode.append(b ^ bl)
    parsed["End Start"]=start
    parsed["ID"] = getstringDecode[0]
    length=int(getstringDecode[1])
    parsed["String Length"]=length
    s = getstringDecode[2:(2 + length)]
    size = ""
    for b in s:
        size = "%s%s " % (size, hex(b))
    parsed["String"]=size
    mac = getstringDecode[(2 + length):10]
    macAddress = ""
    for m in mac:
        macAddress = "%s%s:" % (macAddress, hex(m))
    parsed["MAC Address"] =macAddress
    dataStart=18 + length
    parsed["datastart"] =dataStart
    parsed["Data Header"] = getstringDecode[dataStart:(dataStart + 28)]
    parsed["Data"] = getstringDecode[(dataStart + 28):]

    return parsed

def decodeb64Payload(start,payload):
    mod = 0x7DFDC101
    key=start
    #payloaddecoded = urllib.parse.unquote_plus(payload)
    b64Decoded = base64.b64decode(payload)
    getstringDecode = []
    for b in b64Decoded:
        bl, key = bbs(key, mod)
        getstringDecode.append(b ^ bl)
    return getstringDecode

def decodePayload(start,payload):
    key=start
    mod = 0x7DFDC101
    getstringDecode = []
    for b in payload:
        bl, key = bbs(key, mod)
        getstringDecode.append(b ^ bl)
    return getstringDecode

def processPayload(start,payload):
    first=decodeb64Payload(start,payload)
    start = 0x03EB13
    second=decodePayload(start, first[28:])
    payload=("".join(map(chr,second)))
    return payload.encode("utf-8").decode("utf-16")

def main():
    logo = """
╦┌┐┌┌─┐┬┬┌─┌┬┐  ╔═╗┬─┐┌─┐┬ ┬┌─┐
║│││└─┐│├┴┐ │   ║ ╦├┬┘│ ││ │├─┘
╩┘└┘└─┘┴┴ ┴ ┴   ╚═╝┴└─└─┘└─┘┴  
    """
    banner = """
%s
Turla Mosquito C2 Controller Decode
----------------------------------------------------------------
This tool will decode C2 communication from a Mosquito Controller

To use, supply the encoded portion of the URI string and payload (if applicable)

Examples:
\t python Mosquito_C2_Decryt.py -u qSqwIBu0vaDEgottNI9hiDYHPeoS1mKoq42Ks33RyYcXwZpSZksE.. 
\t python python Mosquito_C2_Decryt.py -uqSqwIBu0vaDEgottNI...  -p gYqzyc0m..
    """ % (
        logo
    )

    # Checks to make sure that file is passed via command line
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner),
    )
    parser.add_argument("-u", "--url", help="Encoded Portion of URI")
    parser.add_argument("-p", "--payload", help="Encoded Payload if POST")

    args = parser.parse_args()

    if args.url and args.payload:
        header=decodeString(args.url)
        if header["ID"]==135:
            d_payload=processPayload(header["Start"],args.payload)
        print("\nDecoded Header\n----------------\nID: %s\nString Length:%s\nString: %s\nMAC Address: %s\n" %(hex(header["ID"]),header["String Length"],header["String"],header["MAC Address"]))
        print("Decoded Payload\n----------------\n%s\n" % (d_payload))
    elif args.url:
        header = decodeString(args.url)
        start = 0x03EB13
        second = decodePayload(start, header["Data"])
        d_payload = ("".join(map(chr, second)))
        print("\nDecoded Header\n----------------\nID: %s\nString Length:%s\nString: %s\nMAC Address: %s\n" % (hex(header["ID"]), header["String Length"], header["String"], header["MAC Address"]))
        print("Decoded Payload\n----------------\n%s\n" % (d_payload))
    else:
        print(banner)

if __name__ == "__main__":
    main()
