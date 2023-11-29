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
