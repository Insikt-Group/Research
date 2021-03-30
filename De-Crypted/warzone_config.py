import pefile
from arc4 import ARC4
from struct import unpack
import argparse

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

def getData(filename):
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

def main():
    parser = argparse.ArgumentParser(description='Warzone Config Extractor')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        required=True, help='Path of Warzone file to unpack')
    args = parser.parse_args()


    dataRaw,sectionSize = getData(args.file)
    key, cipher = getEncodedData(args.file,dataRaw,sectionSize)

    arc4 = ARC4(key)
    configBlock = (arc4.decrypt(cipher))
    config = extractConfig(configBlock)
    for k, v in config.items():
        print(f"{k}: {v}")

if __name__ == "__main__":
    main()

