#!/usr/bin/env python3
"""
Author: randomstr1ng
Description:
Helper script to convert to resolve IP addresses to GeoIP locations using the MaxMind GeoLite2 database. 
"""

import geoip2.database, sys
from argparse import ArgumentParser

banner = """
   _____      ___   ___ ___    ___ ___   _   ___ 
  / _ \ \    / /_\ / __| _ \  / __| _ ) /_\ / __|
 | (_) \ \/\/ / _ \\\\__ \  _/ | (__| _ \/ _ \\\\__ \ 
  \___/ \_/\_/_/ \_\___/_|    \___|___/_/ \_\___/ 
  SAP Attack Surface Discovery Project                                                 
"""


def arguments():
	description = "Script to resolve IP addresses to GeoIP locations using the MaxMind GeoLite2 database."
	usage = "%(prog)s [options]"
	parser = ArgumentParser(usage=usage, description=description)
	target = parser.add_argument_group("Target")
	target.add_argument("-i", "--input-file", dest="IP_LIST", help="Path to IP list file", required=True)
	target.add_argument("-db", "--db-file", dest="GEO_DB", help="Path to GeoLite2 database file", required=True)
	options = parser.parse_args()
	return options

if __name__ == "__main__":
	print(banner)
	options = arguments()
	reader = geoip2.database.Reader(options.GEO_DB)

	d = dict()

	with open(options.IP_LIST, "r") as f:
		data = f.readlines()
		for line in data:
			ip = line.strip("\n")
			try:
				match = reader.city(ip)
				if match.country.name in d:
					d[match.country.name] = d[match.country.name] +1
				else:
					d[match.country.name] = 1
			except:
				pass

	reader.close()

	sorted_list = sorted(d.items(), key = lambda x:x[1], reverse = True)

	for country, count in sorted_list:
		print(f"{country}:{count}")


