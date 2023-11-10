import fcntl
import os
from subprocess import *

import socket
import customtkinter as ctk
import networkx as nx
import PIL

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


import time
import graphviz
import json
import sys
import re
import ipaddress


from getflag import getflag

PLOTX = 0.2
REPLOT = int(os.getenv("REPLOT", 5))  # how often to read buffer and refresh
COLORBY = os.getenv(
    "COLORBY", "port"
)  # graph data field to color code edges by in plotting
TKINT = os.getenv("TKINT", "t").lower() in ["t", "true", "1", "yes", "y"]

ipr = os.popen("ip route|grep -v linkdown")
lines = ipr.readlines()
ipr.close()
dev = re.findall("dev (.+?) ", lines[0])[0]
gw = re.findall("default via (.+?) ", lines[0])[0]
routes = dict()


def non_block_read(output):
    fd = output.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:
        return output.readlines()
    except:
        return ""


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
try:
    IFACE = re.findall("/dev/(.+)", sys.argv[1])[0]
except:
    IFACE = dev
print(dev, " ", myip)
G = nx.DiGraph()


def upsert(ip, G, **data):
    node = G.nodes.get(ip, False)
    if not node:
        flag, country = getflag(ip)
        data["flag"] = flag
        data["shape"] = "image"  # for pyvis
        data["country"] = country
        G.add_node(ip, **data)
        if ipaddress.ip_address(ip) in mynet.hosts() and ip != myip:
            G.nodes.get(ip)["group"] = "arp"
            edge_upsert(myip, ip, G, group="arp")
            edge_upsert(ip, myip, G, group="arp")
    else:
        for k in data.keys():
            if not node.get(k, False):
                G.nodes.get(ip)[k] = data[k]
        image = G.nodes.get(ip)["image"]
        G.nodes.get(ip)["image"] = graphviz.geticon(
            data.get("gson", dict()), default=image
        )


def edge_upsert(cli, srv, G, **data):
    edge = G.edges.get((cli, srv), False)
    if not edge:
        G.add_edge(cli, srv, **data)
    else:
        for k in data.keys():
            if not edge.get(k, False):
                G.edges.get((cli, srv))[k] = data[k]


def hashcolor(strr):
    r = strr.__hash__() % 255
    g = (strr.__hash__() >> 8) % 255
    b = (strr.__hash__() >> 16) % 255
    return "#%02x%02x%02x" % (r, g, b)


def readp0f(g):
    graw = g.rstrip("\n").replace("] ", "|", 1).replace("[", '{"time=', 1)
    gson = {}
    for gg in graw.split("|"):
        gs = gg.split("=")
        gson[gs[0]] = gs[1]
    return gson


upsert(
    myip,
    G,
    label="me",
    group="arp",
    image=graphviz.geticon(dict(), name="james"),
)
upsert(
    gw,
    G,
    label="gateway",
    group="arp",
    image=graphviz.geticon(dict(), name="cisco"),
)
G.add_edge(myip, gw, group="arp", label="default")
G.add_edge(gw, myip, group="arp", label="default")
arp = os.popen("arp -na -i %s" % (IFACE,))
arptable = arp.readlines()
arp.close()
for a in arptable:
    ip = re.findall(" \((.+?)\) ", a)[0]
    if ip != gw and ip != myip:
        upsert(
            ip,
            G,
            group="arp",
            image=graphviz.geticon(dict(), name="computer"),
        )
        G.add_edge(myip, ip, group="arp")
        G.add_edge(ip, myip, group="arp")

if len(sys.argv) > 1:
    p0f = open(sys.argv.pop(), "r")
    args = " ".join(sys.argv)
    if args.find("-j") != -1 or args.find("--json") != -1:
        readjson = True
    else:
        readjson = False
    readlive = False
else:
    try:
        p0f = Popen("(cd p0f; sudo ./p0f|tee ../p0fjson.log )", shell=True, stdout=PIPE)
        readjson = True
        readlive = True
        print("reading live with json-p0f")
    except Exception as e:
        print("cant run json p0f (looking in ./p0f \n", str(e))
        exit(0)
j = 0
begin = time.time()
lastplot = begin


def pyvisplot(G):
    for e in G.edges:
        G.edges.get((e[0], e[1]))["color"] = hashcolor(
            G.get_edge_data(e[0], e[1]).get(COLORBY)
        )
    graphviz.plot(G)


def updateG(G):
    lines = non_block_read(p0f.stdout)
    for g in lines:
        if readjson:
            try:
                gson = json.loads(g.decode())
            except Exception as e:
                print("json error", str(e), g)
        else:  # if using stock p0f
            gson = readp0f(g)
        subj = gson.get("subj")
        ipTo = gson.get("srv").split("/")
        port = ipTo[1]
        ipFrom = gson.get("cli").split("/")
        ipsubj = gson.get(subj).split("/")[0]
        clios = False
        if subj == "cli":
            ipobj = ipTo[0]
            clios = gson.get("os", False)
        if subj == "srv":
            ipobj = ipFrom[0]
        subjIP = ipaddress.ip_address(ipsubj)
        objIP = ipaddress.ip_address(ipobj)
        flagsubj, csubj = getflag(ipsubj)
        flagobj, cobj = getflag(ipobj)
        upsert(
            ipsubj,
            G,
            gson=gson,
            flag=flagsubj,
            country=csubj,
            group="p0f",
            shape="image",
            image=graphviz.geticon(gson),
            os=gson.get("os", False),
        )
        upsert(
            ipobj,
            G,
            group="p0f",
            flag=flagobj,
            country=cobj,
            shape="image",
            image=graphviz.geticon(dict(), name="computer"),
        )
        mod = gson.get("mod", "")
        app = gson.get("app", "")
        link = gson.get("link", "")
        edge_upsert(
            ipFrom[0],
            ipTo[0],
            G,
            port=ipTo[1],
            cli_port=ipFrom[1],
            weight=(
                G.get_edge_data(ipFrom[0], ipTo[0], {}).get(
                    "weight",
                    1 / (float(re.sub("[^0-9]", "", gson.get("dist", "1"))) + 1),
                )
            ),
            mod=mod,
            link=link,
            app=app,
            cli_os=clios,
            group="p0f",
        )
        if mod.find("syn+ack") >= 0:
            edge_upsert(ipTo[0], ipFrom[0], G, mod=mod, link=gson.get("link", ""))
    return G


class tkGraph:
    def __init__(self, G):
        self.G = G
        ctk.set_appearance_mode("dark")
        self.root = ctk.CTk()
        self.root.geometry("1200x1000+200x200")
        self.root.title("p0ing - passive 0S fingerprinting Interative Network Graph")
        # self.root.update()
        self.frame = ctk.CTkFrame(
            master=self.root,
            height=self.root.winfo_height() * 0.95,
            width=self.root.winfo_width() * (1 - PLOTX),
            fg_color="darkblue",
        )
        self.frame.place(relx=PLOTX, rely=0.025)
        self.button = ctk.CTkButton(
            master=self.root,
            text="pyvis plot",
            width=200,
            height=50,
            command=self.pyvisplot,
        )
        self.button.place(relx=0.025, rely=0.25)
        self.exit_button = ctk.CTkButton(
            master=self.root,
            text="Exit",
            width=200,
            height=50,
            command=self.exit,
        )
        self.exit_button.place(relx=0.025, rely=0.85)
        self.fig, self.ax = plt.subplots()
        self.update_window()
        self.after()
        self.root.mainloop()

    def exit(self):
        p0f.kill()
        exit(0)

    def pyvisplot(self):
        pyvisplot(self.G)

    def update_window(self):
        self.ax.cla()
        plt.close()
        self.fig, self.ax = plt.subplots()
        N = len(list(self.G.nodes))
        # pos = nx.kamada_kawai_layout(self.G)
        pos = nx.multipartite_layout(self.G, subset_key="flag")
        pos = nx.spring_layout(self.G, pos=pos, iterations=5)
        colors = []
        colors2 = []
        for e in self.G.edges:
            gv = self.G.get_edge_data(e[0], e[1]).get("link")
            gv2 = self.G.get_edge_data(e[0], e[1]).get(COLORBY)
            colors.append(hashcolor(gv))
            colors2.append(hashcolor(gv2))
        nx.draw_networkx(
            self.G,
            pos=pos,
            node_size=10,
            width=2,
            alpha=0.5,
            ax=self.ax,
            arrows=True,
            edge_color=colors,
            with_labels=True,
        )
        nx.draw_networkx_edges(
            self.G,
            pos=pos,
            ax=self.ax,
            alpha=0.5,
            style=":",
            width=1.5,
            arrows=False,
            edge_color=colors2,
        )
        edge_labels = dict(
            [((n1, n2), G.edges.get((n1, n2)).get("port", "")) for n1, n2 in G.edges]
        )
        nx.draw_networkx_edge_labels(G, pos, edge_labels)
        self.fig.set_size_inches(10, 10)
        tr_figure = self.ax.transData.transform
        # Transform from display to figure coordinates
        tr_axes = self.fig.transFigure.inverted().transform
        icon_size = (self.ax.get_xlim()[1] - self.ax.get_xlim()[0]) * 0.015
        icon_center = icon_size / 4
        for n in self.G.nodes:
            icon = PIL.Image.open(
                self.G.nodes.get(n).get("image", "icons/icons8-my-computer-100.png")
            )
            flag = PIL.Image.open(self.G.nodes.get(n).get("flag", "flags/xx.png"))
            xf, yf = tr_figure(pos[n])
            xa, ya = tr_axes((xf, yf))
            a = plt.axes(
                [
                    xa - icon_center,
                    ya + icon_size / 2 - icon_center,
                    icon_size,
                    icon_size,
                ]
            )
            a.imshow(flag.convert("RGB"))
            a.axis("off")
            a = plt.axes(
                [xa - icon_center, ya + icon_size - icon_center, icon_size, icon_size]
            )
            a.imshow(icon.convert("RGBA"))
            a.axis("off")
        self.ax.axis("off")
        canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        canvas.draw()
        canvas.get_tk_widget().place(relx=PLOTX, rely=0.025)
        self.canvas = canvas
        self.root.update()

    def after(self):
        N = len(list(self.G.nodes))
        self.updateG()
        N2 = len(list(self.G.nodes))
        if N != N2:
            self.update_window()
        self.root.after(REPLOT * 1000, self.after)

    def updateG(self):
        self.G = updateG(self.G)


if TKINT:
    tkGraph(G)
else:
    while 1:
        N = len(list(G.nodes))
        G = updateG(G)
        N2 = len(list(G.nodes))
        if N2 != N:
            pyvisplot(G)
        time.sleep(REPLOT)
