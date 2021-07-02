import argparse
import re
import requests
import json

#https://stackoverflow.com/questions/1604464/twos-complement-in-python
def twos_complement(val, nbits):
    """Compute the 2's complement of int value val"""
    if val < 0:
        val = (1 << nbits) + val
    else:
        if (val & (1 << (nbits - 1))) != 0:
            # If sign bit is set.
            # compute negative value.
            val = val - (1 << nbits)
    return val

# Download document from inquest with given hash
def inQuest_download(sha256):
    url = "https://labs.inquest.net/api/dfi/details?sha256=%s" % (sha256)
    response = requests.request("GET", url,)
    res=response.content
    return json.loads(res)   

# Download document from inquest with given hash    
def inQuest_search(keyword):
    url = "https://labs.inquest.net/api/dfi/search/ext/ext_code?keyword=%s" % (keyword)
    response = requests.request("GET", url,)
    res=response.content
    return json.loads(res)
    
    
def main():
    parser = argparse.ArgumentParser(description='Inquest Cobalt Strike Macro Finder')
    parser.add_argument('-d', '--download', action='store', dest='download',help='Set if you want to save the shellcode as a file')
    args = parser.parse_args()
    
    # Search for "rwxpage" to find Cobalt Strike macros    
    results=inQuest_search("rwxpage")
    count=0
    print("macro_hash,c2")
    # Iterate through each result from the search
    for analysis in results["data"]:
        count += 1
        # Download the document data
        data = inQuest_download(analysis["sha256"])
        # Extract the macro code
        sc = data["data"]["ext_code"]
        # Find the "myArray" variable
        arrays = re.findall("myArray = Array(.+$)", sc,re.DOTALL)
        # For each positive hit of "myArray" we will extract the shellcode to a byte array and then perform
        # twos complement math to correctly transform into the shellcode
        for array in arrays:
            array=array[1:]
            end=array.index(")")
            sc=array[:end]
            sc= sc.split(",")
            shellcode2bin=bytearray()
            for val in sc:
                try:
                    val=val.strip()
                    shellcode2bin.append(twos_complement(int(val),8))
                except ValueError:
                    continue
            # At the end of shellcode, the Teamserver C2 is visable, we can now extract just the C2
            start=shellcode2bin.rindex(0xff)
            end=shellcode2bin.index(0x00,start)
            analysis["sha256"]
            c2=shellcode2bin[start+1:end].decode("utf-8")
            print("%s,%s" % (analysis["sha256"],shellcode2bin[start+1:end].decode("utf-8")))
            if args.download:
                with open(analysis["sha256"],"wb") as shell:
                    shell.write(shellcode2bin)


if __name__ == "__main__":
    main()
