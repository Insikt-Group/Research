
from kamene.all import *
from Crypto.Cipher import ARC4
from struct import *
import argparse
import textwrap

import lznt1


def decodeComm(payload):
    if len(payload) > 16:
        hardCodedKey=[0x21, 0x6e, 0x26, 0x55, 0x2A, 0x4F, 0x25, 0x50, 0x62, 0x24]
        for b in payload[0:4]:
            hardCodedKey.append(int(b))
        key = bytearray(hardCodedKey)
        cipher = ARC4.new(key)
        msg = cipher.decrypt(bytearray(payload))

        return{"Flags":int(unpack("<i", msg[4:8])[0]),"Compressed Size": unpack("<h", msg[8:10])[0],"Decompressed Size":unpack("<h",msg[10:12])[0],
           "Unknown":int(unpack("<i", msg[12:16])[0]),"Data": msg[16:]}
    else:
        return None

def extractPayloads(c2,data):

    a = rdpcap(data)
    payloads={}
    sessions = a.sessions()

    for session in sessions:
        for packet in sessions[session]:
            try:
                if c2 == packet[IP].dst:
                    payloads[packet.time]={"SourceIP":packet[IP].src,"DestinationIP":packet[IP].src, "Payload":bytes(packet[TCP].payload)}
                if c2 == packet[IP].src:
                    payloads[packet.time]={"SourceIP":packet[IP].src,"DestinationIP":packet[IP].src, "Payload":bytes(packet[TCP].payload)}
            except IndexError:
                pass

    payloads = dict(sorted(payloads.items(), key=lambda x: x[0]))
    return payloads

def main():
    logo = """
╦┌┐┌┌─┐┬┬┌─┌┬┐  ╔═╗┬─┐┌─┐┬ ┬┌─┐
║│││└─┐│├┴┐ │   ║ ╦├┬┘│ ││ │├─┘
╩┘└┘└─┘┴┴ ┴ ┴   ╚═╝┴└─└─┘└─┘┴  
    """
    banner = """
%s
RedCharlie PlugX C2 Communication PCAP Decrypt
----------------------------------------------------------------
This tool will decrypt the RedCharlie PlugX C2 Communication from a supplied PCAP.

To use, just pass the full path of the PCAP file and the IP address of the C2.

Examples:
\t python RedCharlie_PlugX_C2_Decrypt.py -f  <FULL PATH TO DOWNLOADED DAT FILE> -i <IP ADDRESS OF C2>
""" % (
        logo
    )

    # Checks to make sure that file is passed via command line
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner),
    )
    parser.add_argument("-f", "--file", help="PCAP File Containing C2 Communication")
    parser.add_argument("-i", "--ip", help="C2 IP Address")

    args = parser.parse_args()

    if args.file and args.ip:
        try:
            payloads = extractPayloads(args.ip, args.file )
            for time, tcp in payloads.items():
                results = decodeComm(tcp["Payload"])
                if results != None:
                    print(
                        "\n-------------------\nTime: %s,Source IP: %s -> Destination IP: %s\n-------------------\n" % (
                        time, tcp["SourceIP"], tcp["DestinationIP"]))
                    for k, v in results.items():
                        print("%s: %s" % (k, v))

        except:
            print("Something didn't work right, ensure this is a PlugX Loader file and "
                  "that the correct arguments were passed")
    else:
        print(banner)

if __name__ == "__main__":
    main()


