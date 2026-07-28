import whois
import sys

site = sys.argv[1]

info = whois.whois(site)

print(info)
