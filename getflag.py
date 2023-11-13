from os import popen
import re
import ipaddress


def getflag(_ip):
    try:
        cip = ipaddress.ip_address(_ip)
        ip = cip.exploded
        b = popen(f"geoiplookup {ip}")
        line = b.readline()
        b.close()
    except Exception as e:
        return "flags/xx.png", "Unknown"
    try:
        ou = re.findall("GeoIP Country Edition: ([A-Z_]{2,5}), (.*)$", line).pop()
        code = ou[0].lower().replace("_", "-")
        name = ou[1]
        return f"flags/{code}.png", name
    except Exception as e:
        return "flags/xx.png", "Unknown"
