#!/usr/bin/python
import mapplot
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

try:
    import jsonofabitch.jsonofabitch as json
except:
    print("JSOB is absent, forced to use strict json")
    import json

import sys
import re
import ipaddress

YES = ["t", "true", "1", "yes", "y", "on"]

from getflag import getflag

PLOTX = 0.2
REPLOT = int(os.getenv("REPLOT", 2))  # how often to read buffer and refresh
LABELS = os.getenv("LABELS", "t").lower() in YES  # how often to read buffer and refresh
ICONS = os.getenv("ICONS", "t").lower() in YES  # how often to read buffer and refresh
TCPDUMP = (
    os.getenv("TCPDUMP", "t").lower() in YES
)  # how often to read buffer and refresh

PASSIVE_ARP = (
    os.getenv("PASSIVE_ARP", "t") in YES
)  # how often to read buffer and refresh
VCTL_SPACE = 0.1
EDGE_LABELS = (
    os.getenv("EDGE_LABELS", "t").lower() in YES
)  # how often to read buffer and refresh
VERBOSE = (os.getenv("VERBOSE", "f").lower() in YES) or ("-v" in sys.argv)
if VERBOSE:
    sys.argv.remove("-v")

EDGE_COLOR_BY = os.getenv(
    "EDGE_COLOR_BY", "port"  # dotted foreground of edge
)  # graph data field to color code edges by in plotting
EDGE_COLOR_BY_BG = os.getenv("EDGE_COLOR_BY_BG", "group")  # BG of edge
TKINT = os.getenv("TKINT", "t").lower() in YES
ipr = os.popen("ip route|grep -v linkdown")
lines = ipr.readlines()
ipr.close()
dev = re.findall("dev (.+?) ", lines[0])[0]
gw = re.findall("default via (.+?) ", lines[0])[0]
routes = dict()
blacklist = set()
traceroute_counter = 0


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
        if not data.get("image", False):
            data["image"] = graphviz.geticon(data.get("gson", dict()))
        try:
            ipc = ipaddress.ip_address(ip)
            data["ip4"] = ip
            if data.get("real_ip",None) is None:
                data["real_ip"]=True
        except:
            if data.get("real_ip",None) is None:
                data["real_ip"]=False
            G.add_node(ip, **data)
            return
        G.add_node(ip, **data)
        if ipc in mynet.hosts() and ip != myip:
            edge_upsert(myip, ip, G, group="arp", dist=1)
            edge_upsert(ip, myip, G, group="arp", dist=1)
    else:
        for k in data.keys():
            if not node.get(k, False):
                G.nodes.get(ip)[k] = data[k]
        image = G.nodes.get(ip)["image"]
        G.nodes.get(ip)["image"] = graphviz.geticon(
            data.get("gson", dict()), default=image
        )
    if VERBOSE:
        print(f"insert {ip}")


def edge_upsert(cli, srv, G, **data):
    if (cli, srv) in blacklist or cli == srv:
        print(cli, " ", srv, str(data))
        return
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


def openarp():
    arp = Popen(
        "sudo tcpdump -vvv -n arp|tee ./arp.log ",
        stdout=PIPE,
        shell=True,
        text=True,
        pipesize=100000,
        bufsize=100000,
    )

    return arp


def parsearp(G, arp):
    global stub
    global stub_by
    reps = []
    reqs = stub
    reqs_by = stub_by
    for l in non_block_read(arp.stdout):
        req = re.findall("who-has ([\.0-9]*) tell (.*), ", l)
        if len(req) > 0:
            tgt, ask = req.pop()
            reqs.append(tgt)
            reqs_by.append(ask)
            if PASSIVE_ARP:
                upsert(tgt, G, group="arp_ask")
                upsert(ask, G, group="arp_active")
                edge_upsert(ask, tgt, G, group="arp_ask", dist=1)
            else:
                upsert(ask, G, group="arp_active")
        rep = re.findall("Reply (.[\.0-9]) is-at", l)
        if len(rep) > 0:
            reps.append(rep.pop())
    if len(reps) == 0:
        stub = reqs
        stub_by = reqs_by
        return
    reqs.reverse()
    reps.reverse()
    reqs_by.reverse()
    if VERBOSE:
        print(reps)
    for j, r in enumerate(reps):
        upsert(r, G, group="arp_active")
        if r in reqs:
            i = reqs.index(r)
            if j == 0:
                stub = reqs[0 :: i - 1]
                stub_by = reqs_by[0 :: i - 1]
                stub.reverse()
                stub_by.reverse()
            reqs.pop(i)
            by = reqs_by.pop(i)
            upsert(by, G, group="arp_active")
            edge_upsert(by, r, G, group="arp_ask", dist=1)
            edge_upsert(r, by, G, group="arp_reply", dist=1)
            if VERBOSE:
                print(by, " ask for ", r)
        else:
            print("arp reply from ", r, " to unknown")


def rm_edge(ip1, ip2):
    global blacklist
    blacklist.add((ip1, ip2))
    blacklist.add((ip2, ip1))
    try:
        G.remove_edge(ip1, ip2)
        G.remove_edge(ip2, ip1)
    except:
        pass


def traceroute(Tip, G, port=False, timeout=5, maxhops=30):
    global traceroute_counter
    traceroute_counter = traceroute_counter + 1
    upsert(Tip, G, group=f"traceroute{traceroute_counter}")
    print("traceroute ", Tip, "port ", port)
    if port:
        cmd = f"sudo traceroute -n -m {maxhops} -T -p {port} {Tip}"
    else:
        cmd = f"traceroute -m {maxhops} -n {Tip}"
    tr = Popen(cmd, shell=True, stdout=PIPE, text=True)
    time.sleep(timeout)
    tr.kill()
    lines = tr.stdout.readlines()
    lastips = [myip]
    lastrealip = myip
    if len(lines) >= maxhops and lines[-1].find(Tip) == -1:
        print("traceroute failure ", Tip)
        return
    rm_edge(Tip, myip)
    # rm_edge(Tip, gw)
    for jj, l in enumerate(lines[1::]):
        ips = re.findall(" (\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}) ", l)
        if len(ips) > 0:
            if VERBOSE:
                print(ips)
            ipnames = []
            for ip in ips:
                if (
                    ipaddress.ip_address(ip).is_private
                    and ip != myip
                    and (ip != gw and lastips[0] == myip)
                ):
                    ipname = (
                        ip
                        + "priv"
                        + hex(str(ip + lastips[0]).__hash__() % (256**2))[2::]
                    )
                    real_ip = False

                else:
                    ipname = ip
                    real_ip = True
                    lastrealip = ip
                ipnames.append(ipname)
                upsert(
                    ipname,
                    G,
                    group=f"traceroute{traceroute_counter}",
                    real_ip=real_ip,
                    last_real_ip=lastrealip,
                    ip4=ip,
                )
                for lip in lastips:
                    edge_upsert(
                        lip, ipname, G, group=f"traceroute{traceroute_counter}", dist=1
                    )
        else:
            ip = "??" + hex(
                (str(Tip.split(".")[0:2]) + str(lastips)).__hash__() % (256**4)
            )
            upsert(
                ip,
                G,
                group=f"traceroute{traceroute_counter}",
                dist=1,
                real_ip=False,
                last_real_ip=lastrealip,
                ip4=None,
            )
            for lip in lastips:
                edge_upsert(lip, ip, G, group=f"traceroute{traceroute_counter}", dist=1)
            ipnames = [ip]
        lastips = ipnames


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
    group="arp_active",
    image=graphviz.geticon(dict(), name="james"),
)
upsert(
    gw,
    G,
    label="gateway",
    group="arp_active",
    image=graphviz.geticon(dict(), name="cisco"),
)
G.add_edge(myip, gw, group="arp", label="default", dist=1)
G.add_edge(gw, myip, group="arp", label="default", dist=1)
arp = os.popen("arp -na -i %s" % (IFACE,))
stub = []
stub_by = []
arptable = arp.readlines()
arp.close()
for a in arptable:
    ip = re.findall(" \((.+?)\) ", a)[0]
    if ip != gw and ip != myip:
        upsert(
            ip,
            G,
            group="arp_active",
            image=graphviz.geticon(dict(), name="computer"),
        )
        G.add_edge(myip, ip, group="arp")
        G.add_edge(ip, myip, group="arp")

if len(sys.argv) > 1:
    if sys.argv[1] == "-j" or sys.argv[1] == "--json":
        p0f = open(sys.argv[-1], "r")
        args = " ".join(sys.argv)
        if args.find("-j") != -1 or args.find("--json") != -1:
            readjson = True
        else:
            readjson = False
        readlive = False
    elif sys.argv[1].lower() == "-t":
        try:
            port = sys.argv[3]
        except:
            port = False
        traceroute(sys.argv[2], G, port=port)
else:
    try:
        print("starting p0f")
        p0f = Popen("(cd p0f; sudo ./p0f|tee ../p0fjson.log )", shell=True, stdout=PIPE)
        readjson = True
        readlive = True
        print("reading live with json-p0f")
    except Exception as e:
        print(
            "cant run json p0f (looking in ./p0f \n read log with -f p0f.log\n", str(e)
        )
        exit(0)
    if TCPDUMP:
        try:
            arp = openarp()
        except Exception as e:
            print("can't open arp tcpdump", str(e))
j = 0
begin = time.time()
lastplot = begin


def pyvisplot(G):
    for e in G.edges:
        G.edges.get((e[0], e[1]))["color"] = hashcolor(
            G.get_edge_data(e[0], e[1]).get(EDGE_COLOR_BY)
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
                continue
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
                    1 / (float(re.sub("[^0-9]", "", gson.get("dist", "20"))) + 1),
                )
            ),
            dist=gson.get("dist", "20"),
            mod=mod,
            link=link,
            app=app,
            cli_os=clios,
            group="p0f",
        )
        if mod.find("syn+ack") >= 0:
            upsert(ipTo[0], G, port=ipTo[1])
            edge_upsert(
                ipTo[0], ipFrom[0], G, mod=mod, link=gson.get("link", ""), group="ack"
            )
    return G


class tkGraph:
    def __init__(self, G):
        bdiff = 0.05  # distance between buttons as fraction of window height
        self.G = G
        ctk.set_appearance_mode("dark")
        self.root = ctk.CTk()
        self.root.geometry("1400x1000+200x200")
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
        self.button.place(relx=0.025, rely=VCTL_SPACE)
        #############################
        #        self.map_button = ctk.CTkButton(
        #            master=self.root,
        #            text="FREE",
        #            width=200,
        #            height=50,
        #            command=self.mapflip,
        #        )
        #        self.map_button.place(relx=0.025, rely=VCTL_SPACE + 2 * bdiff)

        #############################
        self.label_button = ctk.CTkButton(
            master=self.root,
            text="Toggle Node Labels",
            width=200,
            height=50,
            command=self.labelflip,
        )
        self.label_button.place(relx=0.025, rely=VCTL_SPACE + 3 * bdiff)

        #############################
        self.edge_label_button = ctk.CTkButton(
            master=self.root,
            text="Toggle Edge Labels",
            width=200,
            height=50,
            command=self.edge_labelflip,
        )
        self.edge_label_button.place(relx=0.025, rely=VCTL_SPACE + 4 * bdiff)

        self.icon_button = ctk.CTkButton(
            master=self.root,
            text="Toggle icons",
            width=200,
            height=50,
            command=self.icon_flip,
        )
        self.icon_button.place(relx=0.025, rely=VCTL_SPACE + 5 * bdiff)
        #############################
        self.redraw_button = ctk.CTkButton(
            master=self.root,
            text="redraw",
            width=200,
            height=50,
            command=self.update_window,
        )
        self.redraw_button.place(relx=0.025, rely=VCTL_SPACE + 13 * bdiff)
        #############################
        lvalues = [
            f
            for f in nx.__dir__()
            if f.split("_")[-1] == "layout" and len(f.split("_")) > 1
        ]
        otherlayouts = ["none", "geopy_map", "geolocation"]
        self.layout_input = ctk.CTkComboBox(
            self.root,
            width=200,
            height=50,
            values=["multipartite_layout"] + lvalues + otherlayouts,
        )
        self.layout_input.place(relx=0.025, rely=VCTL_SPACE + 9 * bdiff)
        self.layout_input2 = ctk.CTkComboBox(
            self.root,
            width=200,
            height=50,
            values=["spring_layout"] + lvalues + ["none"],
        )
        self.layout_input2.place(relx=0.025, rely=VCTL_SPACE + 11 * bdiff)
        #############################
        self.layout_input_opts = ctk.CTkComboBox(
            self.root,
            width=200,
            height=50,
            values=[
                '{"subset_key": "group"}',
                '{"iterations": 50}',
            ],
        )
        self.layout_input_opts.place(relx=0.025, rely=VCTL_SPACE + 10 * bdiff)
        #############################
        self.layout_input_opts2 = ctk.CTkComboBox(
            self.root,
            width=200,
            height=50,
            values=[
                '{"iterations": 50}',
                '{"subset_key": "group"}',
            ],
        )
        self.layout_input_opts2.place(relx=0.025, rely=VCTL_SPACE + 12 * bdiff)
        #############################
        #############################
        #############################
        self.traceroute_button = ctk.CTkButton(
            master=self.root,
            text="traceroute",
            width=200,
            height=50,
            command=self.traceroute_flip,
        )
        self.traceroute_button.place(relx=0.025, rely=VCTL_SPACE + 7 * bdiff)
        #############################
        self.tracert_input = ctk.CTkComboBox(
            self.root, width=200, height=50, values=list(self.G.nodes)
        )

        self.tracert_input.place(relx=0.025, rely=VCTL_SPACE + 6 * bdiff)
        #############################
        self.save_button = ctk.CTkButton(
            master=self.root,
            text="Save",
            width=200,
            height=50,
            command=self.save,
        )
        self.save_button.place(relx=0.025, rely=0.90)
        self.save_input = ctk.CTkComboBox(
            self.root,
            width=200,
            height=50,
            values=[
                f + f", p0ing.{f.split('_')[-1]}"
                for f in nx.__dir__()
                if f[0:5] == "write"
            ],
        )

        self.save_input.place(relx=0.025, rely=0.85)
        #############################

        self.exit_button = ctk.CTkButton(
            master=self.root,
            text="Exit",
            width=200,
            height=50,
            command=self.exit,
        )
        self.exit_button.place(relx=0.025, rely=0.95)

        #############################
        self.fig, self.ax = plt.subplots()
        self.update_window()
        self.after()
        self.root.mainloop()
        self.traceroute_flip()

    def exit(self):
        p0f.kill()
        try:
            arp.kill()
        except:
            print("cant kill arp tcpdump")
        exit(0)

    def save(self):
        fun, outf = self.save_input.get().split(", ")
        getattr(nx, fun)(self.G, outf)
        print(fun, " saved to ", outf)

    def edge_labelflip(self):
        global EDGE_LABELS
        EDGE_LABELS = EDGE_LABELS ^ True
        self.update_window()

    def labelflip(self):
        global LABELS
        LABELS = LABELS ^ True
        self.update_window()

    def prune_flip(self):
        global PRUNE
        PRUNE = PRUNE ^ True
        self.update_window()

    def traceroute_flip(self):
        host = self.tracert_input.get()
        hsplit = host.split(":")
        if len(hsplit) == 2:
            port = hsplit[1]
            host = hsplit[0]
            upsert(host,self.G)
        else:
            upsert(host,self.G)
            port = self.G.nodes.get(host).get("port", False)
        traceroute(host, self.G, port=port)

    def icon_flip(self):
        global ICONS
        ICONS = ICONS ^ True
        self.update_window()

    def pyvisplot(self):
        pyvisplot(self.G)

    def update_window(self):
        self.tracert_input.configure(values=list(self.G.nodes))
        self.ax.cla()
        plt.close()
        self.fig, self.ax = plt.subplots()
        N = len(list(self.G.nodes))
        layout1 = self.layout_input.get()
        layout2 = self.layout_input2.get()
        MAP = False
        if layout1 == "geopy_map":
            MAP = True
            self.fig.set_size_inches(12, 10)
            pos = mapplot.geoplot(self.G, None, draw_map=True)
            layout2 = "none"
        elif layout1 == "geolocation":
            geopos = mapplot.geoplot(self.G, None, draw_map=False)
            pos = mapplot.mkgeo_cluster_layout(G, geopos)
        elif layout1 != "none":
            try:
                opts = json.loads(self.layout_input_opts.get())
                pos = getattr(nx, layout1)(self.G, **opts)
            except:
                print("error in layout 1, using spring")
                pos = nx.spring_layout(self.G, iterations=50)
        else:
            print("no layout 1")
        if layout2 != None:
            try:
                opts2 = json.loads(self.layout_input_opts2.get())
                opts2["pos"] = pos
                pos = getattr(nx, layout2, lambda G, x: x)(self.G, **opts2)
            except Exception as e:
                print("error in step 2 of layout", e)
        colors = []
        colors2 = []
        if not MAP:
            self.fig.set_size_inches(10, 10)
        for e in self.G.edges:
            gv = self.G.get_edge_data(e[0], e[1]).get(EDGE_COLOR_BY_BG)
            gv2 = self.G.get_edge_data(e[0], e[1]).get(EDGE_COLOR_BY)
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
            with_labels=LABELS,  # ip labels
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
        if EDGE_LABELS:
            edge_labels = dict(
                [
                    ((n1, n2), G.edges.get((n1, n2)).get("port", ""))
                    for n1, n2 in G.edges
                ]
            )
            nx.draw_networkx_edge_labels(G, pos, edge_labels)
        if not MAP and ICONS:
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
                xf, yf = tr_figure(
                    pos[n],
                )
                xa, ya = tr_axes((xf, yf))
                a = plt.axes(
                    [
                        xa - icon_center,
                        ya + icon_size / 2 - icon_center,
                        icon_size,
                        icon_size,
                    ]
                )
                a.imshow(flag.convert("RGB"), zorder=1)
                a.axis("off")
                a = plt.axes(
                    [
                        xa - icon_center,
                        ya + icon_size - icon_center,
                        icon_size,
                        icon_size,
                    ]
                )
                a.imshow(icon.convert("RGBA"), zorder=1)
                a.axis("off")
        self.ax.axis("off")
        canvas = FigureCanvasTkAgg(self.fig, master=self.root)
        canvas.draw()
        canvas.get_tk_widget().place(relx=PLOTX, rely=0.025)
        self.canvas = canvas
        self.root.update()

    def after(self):
        N = len(list(self.G.nodes))
        self.parsearp()
        self.updateG()
        N2 = len(list(self.G.nodes))
        if N != N2:
            self.update_window()
        self.root.after(REPLOT * 1000, self.after)

    def parsearp(self):
        parsearp(self.G, arp)

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
