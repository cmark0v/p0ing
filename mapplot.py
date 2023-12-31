import __main__
import ipaddress
import json
import os
from matplotlib import pyplot as plt
from mpl_toolkits import basemap
import numpy as np
from dotenv import load_dotenv
import networkx as nx

YES = ["t", "true", "1", "yes", "y", "on"]
load_dotenv()
IPINFOTOKEN = os.getenv("IPINFOTOKEN", "")
from geopy import distance

VERBOSE = os.getenv("VERBOSE", "")
ICONS = os.getenv("ICONS", "t").lower() in YES  # how often to read buffer and refresh


def mkgeo_cluster_layout(G, pos_map):
    lons, lats = getgps(G)
    pos_geo = {n: (lats[i], lons[i]) for i, n in enumerate(G.nodes)}
    D = nx.Graph()
    for j in pos_geo.keys():
        D.add_node(j)
        for k in D.nodes:
            D.add_edge(
                j,
                k,
                weight=1
                / (np.sqrt(distance.geodesic(pos_geo[j], pos_geo[k]).kilometers) + 0.1),
            )
    pos = nx.spring_layout(D, pos=pos_map, k=10, iterations=50, weight="weight")
    return pos


def get_gps_of_node(n):
    loc = n.get("ipinfo_loc", False)
    if not loc:
        if n.get("real_ip", True):
            info = getipinfo(n.get("ip4"))
        else:
            info = getipinfo(n.get("last_real_ip", ""))
        if VERBOSE:
            print(info)
        lat, log = info.get("loc", "0,0").split(",")
        for k in info.keys():
            n["ipinfo_" + k] = info[k]
    else:
        lat, log = loc.split(",")
    return lat,log

def getgps(G):
    lats = []
    logs = []
    for e in G.nodes:
        lat,log = get_gps_of_node(G.nodes[e])
        lats.append(float(lat))
        logs.append(float(log))
    return logs, lats


def getipinfo(ip):
    try:
        ippriv = ipaddress.ip_address(ip).is_private
        # if the ip is a private network reserved range
        # the only such ips that should make it here are the local ones on the LAN, others are masked
    except:
        ippriv = True
    if ippriv:
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


def geoplot(G, ax=None, draw_map=True):
    m = basemap.Basemap(
        projection="cyl",
        llcrnrlat=-75,
        urcrnrlat=75,
        llcrnrlon=-150,
        urcrnrlon=150,
        lat_ts=20,
        resolution="c",
        ax=ax,
    )
    lons, lats = getgps(G)
    pos = {n: m(lons[i], lats[i]) for i, n in enumerate(G.nodes)}
    if draw_map:
        m.drawcoastlines(ax=ax, zorder=1)
        m.drawcountries(ax=ax, zorder=1)
        if getattr(__main__, "ICONS", True):
            for n in G.nodes:
                plt.imshow(
                    plt.imread(
                        G.nodes.get(n).get("image", "icons/icons8-james-brown-100.png")
                    ),
                    extent=[pos[n][0], pos[n][0] + 10, pos[n][1], pos[n][1] + 10],
                )
    return pos
