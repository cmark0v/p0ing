from os import popen
import re
import ipaddress


def getflag(_ip):
    try:
        cip = ipaddress.ip_address(_ip)
        ip = cip.exploded
    except:
        return f"flags/xx.png", "Unknown"
    b = popen(f"geoiplookup {ip}")
    line = b.readline()
    b.close()
    try:
        ou = re.findall("GeoIP Country Edition: ([A-Z_]{2,5}), (.*)$", line).pop()
        code = ou[0].lower().replace("_", "-")
        name = ou[1]
        return f"flags/{code}.png", name
    except:
        return f"flags/xx.png", "Unknown"
