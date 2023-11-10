import matplotlib.pyplot as plt
import networkx as nx
from networkx.algorithms.approximation.dominating_set import min_weighted_dominating_set
import pyvis
from grave import plot_network
from pyvis.network import Network

options = {
    "edges": {
        "arrows": {"to": {"enabled": True}},
        "color": {"inherit": True},
        "smooth": {"forceDirection": "none"},
    },
    "interaction": {
        "hover": True,
        "keyboard": {"enabled": True},
        "multiselect": True,
    },
    "configure": True,
    "manipulation": {"enabled": True},
    "physics": {
        "hierarchicalRepulsion": {
            "centralGravity": 3.5,
            "nodeDistance": 160,
            "avoidOverlap": 0.06,
        },
        "minVelocity": 0.75,
        "solver": "hierarchicalRepulsion",
    },
}
oslist = {
    "BaiduSpider": "phish",
    "Blackberry": "android",
    "FreeBSD": "freebsd",
    "Linux": "linux",
    "masscan": "bad",
    "NeXTSTEP": "cisco",
    "Nintendo": "ios",
    "OpenBSD": "openbsd",
    "OpenVMS": "cisco",
    "p0f": "bad",
    "Solaris": "sun",
    "Tru64": "cisco",
    "Windows": "win-95",
    "HP-UX": "computer",
    "Mac OS X": "osx",
}
icons = {
    "android": "icons/icons8-android-96.png",
    "cisco": "icons/icons8-cisco-router-96.png",
    "freebsd": "icons/icons8-freebsd-96.png",
    "ios": "icons/icons8-iphone-96.png",  #
    "linux": "icons/icons8-linux-96.png",
    "???": "icons/icons8-anonymous-mask-96.png",
    "bad": "icons/icons8-anonymous-mask-96.png",
    "osx": "icons/icons8-mac-client-96.png",
    "win-95": "icons/icons8-windows-95-96.png",
    "win-xp": "icons/icons8-windows-xp-96.png",
    "openbsd": "icons/icons8-blow-fish-96.png",
    "james": "icons/icons8-james-brown-100.png",
    "computer": "icons/icons8-my-computer-100.png",
    "phish": "icons/icons8-phishing-96.png",
    "sun": "icons/icons/icons8-sun-96.png",
}


def geticon(gson, name="computer", default=False):
    if default:
        icon = default
    else:
        icon = icons.get(name, icons["computer"])
    os = gson.get("os", False)
    if not os:
        return icon
    else:
        for ost in list(oslist.keys()):
            if os.lower().find(ost.lower()) > -1:
                icon = icons.get(oslist.get(ost))
        return icon


def color_dict(attrs, fields={"group"}):
    lildict = {j: attrs.get(j, False) for j in fields}
    h = hash(str(lildict.items()))
    color = "#"
    for j in range(3):
        color = color + "%.2x" % ((h >> 8 * j) % 256,)
    return color


def edge_font_styler(attributes):
    return {
        "font_size": 4,
        "font_weight": 0.75,
        "font_color": color_dict(attributes, fields={"guess"}),
    }


def node_font_styler(attributes):
    return {
        "font_size": 4,
        "font_weight": 0.75,
    }


def plot_grave(network,ax):
    plot_network(
        network,
        ax=ax
    )


def plot(G):
    net = Network(
        notebook=True,
        cdn_resources="in_line",
        select_menu=True,
        filter_menu=True,
        directed=True,
    )
    net.from_nx(G)
    net.options = options
    net.show("p0ing.html")
