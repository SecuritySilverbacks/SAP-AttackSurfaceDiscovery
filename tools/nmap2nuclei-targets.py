#!/usr/bin/env python3
"""
Author: randomstr1ng
Description:
Helper script to convert nmap scan xml results to a list of ip:port pairs, which can be used as a target list for nuclei scanner.
If a hostname was provided as a input of nmap instead of an ip address, the hostname will be used within the target list. 
"""

import xmltodict, json, os
from argparse import ArgumentParser

banner = """
   _____      ___   ___ ___    ___ ___   _   ___ 
  / _ \ \    / /_\ / __| _ \  / __| _ ) /_\ / __|
 | (_) \ \/\/ / _ \\\\__ \  _/ | (__| _ \/ _ \\\\__ \ 
  \___/ \_/\_/_/ \_\___/_|    \___|___/_/ \_\___/ 
  SAP Attack Surface Discovery Project                                                 
"""

def arguments():
        description = "Script to enumerate capabilities of the SAP Start Service"
        usage = "%(prog)s [options]"
        parser = ArgumentParser(usage=usage, description=description)
        target = parser.add_argument_group("Target")
        target.add_argument("-i", "--input-file", dest="IN_FILE", help="Input file / filename", required=True)
        target.add_argument("-o", "--output-file", dest="OUT_FILE", help="Input file / filename", required=True)
        target.add_argument("-v", "--verbose", dest="VERBOSE", help="enable verbose output", action="store_true")
        options = parser.parse_args()
        return options

def read_nmap_result(IN_FILE):
	with open(IN_FILE, "r") as file:
		return json.dumps(xmltodict.parse(file.read()))

def main():
    print(banner)
    options = arguments()
    print("[*] Generating Target list...")
    if options.VERBOSE:
        print("\n[*] Targets:")
    data = json.loads(read_nmap_result(options.IN_FILE))
    with open(options.OUT_FILE, "w") as file:
        if int(data["nmaprun"]["runstats"]["hosts"]["@total"]) > 1:
            for host in data["nmaprun"]["host"]:
                if host["hostnames"] != None:
                    for entry in host["hostnames"]["hostname"]:
                        try:
                            if entry["@type"] == "user":
                                target = entry["@name"]
                        except:
                            if entry == "@name" or entry == "@type":
                                target = host["address"]["@addr"]
                            break
                else:
                    target = host["address"]["@addr"]
                for port in host["ports"]["port"]:
                    target_port = port["@portid"]
                    if options.VERBOSE:
                        print(f'{target}:{target_port}')
                    file.writelines(f'{target}:{target_port}\n')
        else:
            if data["nmaprun"]["host"]["hostnames"]["hostname"].get("@type") == "user":
                 target = data["nmaprun"]["host"]["hostnames"]["hostname"].get("@name")
            else:
                 target = data["nmaprun"]["host"]["address"].get("@addr")
            for port in data["nmaprun"]["host"]["ports"].get("port"):
                target_port = port["@portid"]
                if options.VERBOSE:
                    print(f'{target}:{target_port}')
                file.writelines(f'{target}:{target_port}\n')

    print(f"\n[*] Targets written to {os.path.abspath(options.OUT_FILE)}")
    print("[*] Done")

main()