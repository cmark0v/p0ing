import os
import ipaddress
import re


def procarp():
    ipr = os.popen("ip route|grep -v linkdown")
    lines = ipr.readlines()
    ipr.close()
    dev = re.findall("dev (.+?) ", lines[0])[0]
    gw = re.findall("default via (.+?) ", lines[0])[0]
    routes = dict()

    for l in lines:
        try:
            netip = re.findall(
                f"(.*?) dev {dev} proto kernel scope link src (.*?) ", l
            ).pop()
            myip = netip[1]
            mynet = ipaddress.ip_network(netip[0])
            routes[myip] = []
            routes[myip].append(
                re.findall(
                    f"(.*) dev {dev} proto kernel scope link src {myip} metric 100", l
                ).pop()
            )
        except Exception as e:
            print(e)
    return dev, myip, gw, mynet, routes
