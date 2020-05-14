import pefile
import time
from struct import *
import argparse
import textwrap

key1=1
key2=0
key3=0

def initializeArray(count):
    index = 0
    blob = []
    while count > 0:
        blob.append(index)
        index += 1
        count -= 1
    return blob

def eax2ax(number):
    ax=0
    hexR=hex(number)
    hexR = hexR[2:]
    if len(hexR) > 4:
        ax = int(hexR[-4:], 16)
    else:
        ax=number
    return ax

def highLow(number):
    eax=0
    edx=0
    hexR=hex(number)
    hexR=hexR[2:]
    if len(hexR)<9:
        eax=number
        edx=0
    else:
        index=len(hexR[:-8])
        edx=int(hexR[:-8], 16)

    return edx,eax

def poisen(blob,seed,count,displacement,v2):
    global key1
    global key2
    divisor=(v2-displacement) + 1
    while count > 0:
        seed*=key1
        seed+=key2
        seed=eax2ax(seed)
        seed_mod=seed % divisor
        seed=seed * key1
        seed=seed + key2
        index_1=seed_mod + displacement
        seed=eax2ax(seed)#possible new start
        seed_mod=seed % divisor
        try:
            const_1=blob[index_1]
        except IndexError:
            print(hex(index_1))
        index_2=seed_mod + displacement
        const_2=blob[index_2]
        blob[index_1] = const_2
        blob[index_2] = const_1
        count-=1
    return blob,seed

def generateKeyBlob():

    global key3

    blob=initializeArray(0x100)
    offset=0x80
    init=0x10624dd3

    #Generate number of rounds for each sequence
    const=key3 * init
    count_h,count_l=highLow(const)
    count=count_h >> 6
    count=count * 0x3e8
    count=key3-count
    count=count+offset

    #Sequence 1
    offset_r1=offset-0x61 # 1f
    displacement=offset-0x7f
    blob,seed=poisen(blob,key3,count,displacement,offset_r1)

    #Sequence 2
    displacement=offset-0x60
    offset_r2=offset-1
    blob,seed=poisen(blob,seed,count,displacement,offset_r2)

    #Sequence 3
    displacement=offset
    offset_r3=offset+0x7f
    blob,seed=poisen(blob,seed,count,displacement,offset_r3)

    #create keyBlog for decryption of strings
    keyBlob=initializeArray(0x100)
    c=0
    for b in blob:
        keyBlob[b]=c
        c+=1
    return blob,keyBlob

def sd(keyBlob,codestr):

    ss = []
    CountStringOpcode = 4
    leng = len(codestr) - CountStringOpcode
    if leng < 0:
        leng = 0
    lenBlock = leng // CountStringOpcode
    nb = 0
    rb = 0
    delta = 0
    n = 0
    i = 0

    while (n < leng):
        if rb == 0:
            nb += 1
            if (nb <= CountStringOpcode):
                delta = codestr[i] - 0x61
                i += 1
                rb = lenBlock
            else:
                rb = leng - n
        if (rb > 0):
            rb -= 1
            c = codestr[i]
            if c < 32:
                min = 1
                max = 31
            elif c < 128:
                min = 32
                max = 127
            else:
                min = 128
                max = 255
            c = keyBlob[c]
            c -= delta
            if (c < min):
                c = max - min + c
            ss.append(c)
            i += 1
            n += 1
    s=""
    try:
        s="".join(map(chr, ss))
    except ValueError:
        s=ss
    return s

def getData(filename):
    raw = 0
    pe = pefile.PE(filename)

    try:
        for section in pe.sections:
            if '.data' in str(section.Name):
                raw = section.PointerToRawData
    except OSError as e:
        print(e)
    except pefile.PEFormatError as e:
        print("[-] PEFormatError: %s" % e.value)
    return raw

def getEncodedData(filename,dataRaw,configItems):
    encryptedValues={}
    with open(filename, 'rb') as f:
        f.read(dataRaw)
        for config in configItems:
            end=False
            tBA = bytearray()
            while end==False:
                if config == "PUBLIC_KEY":
                    current=f.tell()
                    temp=f.read(87)
                    null=f.read(8)
                    if null == b'\x00\x00\x00\x00\x00\x00\x00\x00':
                        f.seek(current)
                        for x in range(87):
                            t=f.read(1)
                            tBA.append(int.from_bytes(t, "little"))
                        break
                    else:
                        tBA.append(int.from_bytes(b'f', "little"))
                        break
                t=f.read(1)
                #print(t)
                #print(len(tBA))
                if t == b'\x00':
                    while True:
                        if t == b'\x00':
                            current = f.tell()
                            t = f.read(1)
                        else:
                            f.seek((current))
                            break
                    break
                else:
                    tBA.append(int.from_bytes(t,"little"))
            encryptedValues[config]=tBA
    return encryptedValues

def main():

    configItems_V1 = ["PERIOD_CONTACT", "UNKNOWN1", "ADMIN_PANEL_HOSTS", "ADMIN_AZ", "USER_AZ", "ADMIN_PASSWORD",
                      "UNKNOWN2", "VIDEO_SERVER_IP",
                      "UNKNOWN3", "FLAGS_VIDEO_SERVER", "UNKNOWN4", "MISC_STATE", "UNKNOWN5", "DATEWORK", "UNKNOWN6",
                      "UNKNOWN7", "PREFIX_NAME", "UNKNOWN8", "RAND_VECTOR", "PUBLIC_KEY"]
    configItems_V2 = ["PERIOD_CONTACT", "UNKNOWN1", "ADMIN_PANEL_HOSTS", "ADMIN_AZ", "USER_AZ", "UNKNOWN2",
                      "ADMIN_PASSWORD", "UNKNOWN3",
                      "VIDEO_SERVER_IP", "UNKNOWN4", "FLAGS_VIDEO_SERVER", "UNKNOWN5", "MISC_STATE", "UNKNOWN6",
                      "DATEWORK", "UNKNOWN7", "UNKNOWN8", "PREFIX_NAME", "UNKNOWN9", "RAND_VECTOR", "PUBLIC_KEY"]
    encryptedValues = {}
    logo = """
╦┌┐┌┌─┐┬┬┌─┌┬┐  ╔═╗┬─┐┌─┐┬ ┬┌─┐
║│││└─┐│├┴┐ │   ║ ╦├┬┘│ ││ │├─┘
╩┘└┘└─┘┴┴ ┴ ┴   ╚═╝┴└─└─┘└─┘┴  
    """
    banner = """
%s
Carbanak Configuration Decoder
----------------------------------------------------------------
This tool will decode the configuration settings for the CARBANAK Backdoor. More specifically, this script will work
with the 64bit dll versions that are commonly embedded in BIOLOAD and BOOSTWRITE binaries.

While the encryption method is the same for all Carbanak samples the locations of decryption key is different
depending on the sample which is why supply a non 64 bit dll version may cause issues.

This script can be modified to decode other Carbanak variants, and in the future Insikt group may do so.

To use, just pass the full path of the Carbanak file to decode.

Examples:
\t python Carbanak_Config_Decode.py -f  <FULL PATH TO CARBANAK FILE>
""" % (
        logo
    )

    # Checks to make sure that file is passed via command line
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner),
    )
    parser.add_argument("-f", "--file", help="CARBANAK FILE")

    args = parser.parse_args()

    if args.file:

        dataRaw = getData(args.file)
        VERSION1=False
        encryptedValues = getEncodedData(args.file, dataRaw,configItems_V1)
        if encryptedValues["PUBLIC_KEY"] ==0x57:
            VERSION1=True
        if VERSION1==False:
            while True:
                if len(encryptedValues["PUBLIC_KEY"]) == 0x57:
                    break
                else:
                    dataRaw+=1
                    encryptedValues = getEncodedData(args.file, (dataRaw),configItems_V2)

        global key1
        global key2
        global key3

        RV=encryptedValues["RAND_VECTOR"][-6:]
        key1=unpack("<H", RV[2:4])[0]
        key2=unpack("<H", RV[4:6])[0]
        key3=unpack("<H", RV[:2])[0]

        blob,keyBlob=generateKeyBlob()
        print("""\nThere may junk looking data in the output, please look closely, the presence of junk data doesn't
automatically mean the script did not work. Items not configured during the building phase will contain junk
values. To ensure the script works, you should at the least see correct values in the Period Contact,
Admin Password,Misc State and Prefix Name fields. You should also see domains or IPs defined in the
Video Server IP or Admin Panel Hosts fields (but not necessarily both)\n""")
        for key,value in encryptedValues.items():
            decoded=sd(keyBlob,value)
            print("%s: %s" % (key,decoded))
    else:
        print(banner)

if __name__ == "__main__":
    main()
