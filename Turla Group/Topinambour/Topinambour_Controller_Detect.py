import socket
import argparse
import textwrap
import os
from struct import *


def scanController(HOST, PORT):
    valid = False
    command = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            data = s.recv(4)
            if len(data) == 4:
                length = unpack("<I", data)[0]
            data = s.recv()
            if len(data) == length:
                valid = True
                command = data.decode("utf-16")
    except OSError:
        pass
    return valid, command


def main():
    logo = """
╦┌┐┌┌─┐┬┬┌─┌┬┐  ╔═╗┬─┐┌─┐┬ ┬┌─┐
║│││└─┐│├┴┐ │   ║ ╦├┬┘│ ││ │├─┘
╩┘└┘└─┘┴┴ ┴ ┴   ╚═╝┴└─└─┘└─┘┴  
    """
    banner = """
%s
Turla Topinambour Controller Detect
----------------------------------------------------------------
This tool will connect to a single or list of IP's to see if they are Topinambour clients

To use, include a IP or file of IP's. 

Examples:
\t python Topinambour_Controller_Detect.py -i IPADDRESS
\t python Topinambour_Controller_Detect.py -l IPADDRESS.txt
""" % (
        logo
    )

    # Checks to make sure that file is passed via command line
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner),
    )
    parser.add_argument("-i", "--ip", help="Single IP to Scan")
    parser.add_argument("-l", "--list", help="Full path of file with IP's")

    args = parser.parse_args()

    PORT = 13277
    if args.ip:
        HOST = args.ip
        print("\nScanning %s\n-----------------------" % (args.ip))
        valid, command = scanController(HOST, PORT)
        if valid == True:
            print(
                "Response from host is indicitive of a Topinambour controller.\nPlease visually verify the command sent is a valid Windows Command.\nCommand:%s\n"
                % (command)
            )
    elif args.list:
        if os.path.isfile(args.list):
            ips = open(args.list, "r")
            for ip in ips:
                ip = ip.rstrip()
                print("\nScanning %s\n-----------------------" % (ip))
                valid, command = scanController(ip, PORT)
                if valid == True:
                    print(
                        "Response from host is indicitive of a Topinambour controller.\nPlease visually verify the command sent is a valid Windows Command.\nCommand:%s\n"
                        % (command)
                    )
        else:
            print("Not a valid file")
    else:
        print(banner)


if __name__ == "__main__":
    main()
