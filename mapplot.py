import ipaddress
import json
import os
from matplotlib import pyplot as plt
from mpl_toolkits import basemap
import numpy as np
from dotenv import load_dotenv

load_dotenv()
IPINFOTOKEN = os.getenv("IPINFOTOKEN", "")


def getgps(G):
    lats = []
    logs = []
    for e in G.nodes:
        loc = G.nodes.get(e).get("ipinfo_loc", False)
        if not loc:
            info = getipinfo(e)
            #print(info)
            lat, log = info.get("loc", "0,0").split(",")
            for k in info.keys():
                G.nodes.get(e)["ipinfo_" + k] = info[k]
        else:
            lat, log = loc.split(",")
        lats.append(float(lat))
        logs.append(float(log))
    return logs, lats


def getipinfo(ip):
    if ipaddress.ip_address(ip).is_private:
        b = ""
        f = os.popen(f"curl https://ipinfo.io/{b}?token={IPINFOTOKEN} 2>/dev/null", "r")
    else:
        f = os.popen(
            f"curl https://ipinfo.io/{ip}?token={IPINFOTOKEN} 2>/dev/null", "r"
        )
    dat = f.read()
    f.close()
    try:
        ipinfo = json.loads(dat)
        return ipinfo
    except Exception as e:
        return dict()


def geoplot(G, ax):
    m = basemap.Basemap(
        projection="cyl",
        llcrnrlat=-75,
        urcrnrlat=75,
        llcrnrlon=-180,
        urcrnrlon=180,
        lat_ts=20,
        resolution="c",
        ax=ax,
    )
    m.drawcoastlines(ax=ax,zorder=1)
    m.drawcountries(ax=ax,zorder=1)
    lons, lats = getgps(G)
    pos = {n: m(lons[i], lats[i]) for i, n in enumerate(G.nodes)}
    return pos
