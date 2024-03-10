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

def eval_entry(item):
    if item.get("hostnames") == None:
        return item["address"].get("@addr")
    else:
        for entry in item["hostnames"]["hostname"]:
            if entry["@type"] == "user":
                return entry["@name"]
            else:
                pass

def main():
    print(banner)
    options = arguments()
    print("[*] Generating Target list...")
    if options.VERBOSE:
        print("\n[*] Targets:")
    data = json.loads(read_nmap_result(options.IN_FILE))
    with open(options.OUT_FILE, "w") as file:
        # only if single host
        if data["nmaprun"]["runstats"]["hosts"].get("@total") == "1":
            target = eval_entry(data["nmaprun"]["host"])
            for port in data["nmaprun"]["host"]["ports"]["port"]:
                if options.VERBOSE:
                    print(f'{target}:{port.get("@portid")}')
                file.writelines(f'{target}:{port.get("@portid")}\n')

        # only if multiple hosts
        else:
            for item in data["nmaprun"]["host"]:
                target = eval_entry(item)
                for port in item["ports"]["port"]:
                    if options.VERBOSE:
                        print(f'{target}:{port.get("@portid")}')
                    file.writelines(f'{target}:{port.get("@portid")}\n')

    print(f"\n[*] Targets written to {os.path.abspath(options.OUT_FILE)}")
    print("[*] Done")

main()