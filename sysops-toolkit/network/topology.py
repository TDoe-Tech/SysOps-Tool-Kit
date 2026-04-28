"""
network/topology.py
CompTIA Network+ Module — Network Topology Visualizer

Demonstrates: Network topology concepts, node/edge relationships,
visual representation of network segments — Network+ objectives.

Requires: networkx, matplotlib
"""

import json

try:
    import networkx as nx
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    GRAPH_AVAILABLE = True
except ImportError:
    GRAPH_AVAILABLE = False


DEVICE_COLORS = {
    "router": "#1d4ed8",
    "switch": "#7c3aed",
    "server": "#b45309",
    "workstation": "#15803d",
    "laptop": "#15803d",
    "raspberry pi foundation": "#be123c",
    "apple": "#374151",
    "microsoft (hyper-v)": "#0369a1",
    "cisco systems": "#1d4ed8",
    "unknown vendor": "#6b7280",
    "default": "#6b7280"
}


def _guess_device_type(host: dict) -> str:
    """Guess device type from hostname or vendor."""
    hostname = host.get("hostname", "").lower()
    vendor = host.get("vendor", "").lower()

    if "router" in hostname or "gateway" in hostname:
        return "router"
    if "switch" in hostname:
        return "switch"
    if "server" in hostname or "srv" in hostname:
        return "server"
    if "mac" in hostname or "apple" in vendor:
        return "laptop"
    return "workstation"


def build_topology(scan_results: dict, output_path: str = "topology.png"):
    """
    Build and save a network topology graph from scan results.

    Args:
        scan_results: Output from scanner.scan_network()
        output_path: Where to save the PNG
    """
    if not GRAPH_AVAILABLE:
        print("[Topology] networkx/matplotlib not installed. Run: pip install networkx matplotlib")
        return None

    G = nx.Graph()
    hosts = scan_results.get("hosts", [])
    subnet = scan_results.get("subnet", "Network")

    # Add router/gateway node (first host or .1 address)
    gateway_ip = hosts[0]["ip"] if hosts else "Gateway"
    G.add_node(gateway_ip, label="Gateway\n" + gateway_ip, type="router")

    # Add all other hosts connected to gateway
    for host in hosts[1:]:
        ip = host["ip"]
        device_type = _guess_device_type(host)
        label = f"{host['hostname']}\n{ip}\n{host['vendor']}"
        G.add_node(ip, label=label, type=device_type)
        G.add_edge(gateway_ip, ip)

    # Layout
    pos = nx.spring_layout(G, seed=42, k=2.5)

    # Node colors
    node_colors = []
    for node in G.nodes():
        node_type = G.nodes[node].get("type", "default")
        color = DEVICE_COLORS.get(node_type, DEVICE_COLORS["default"])
        node_colors.append(color)

    # Draw
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.set_facecolor("#f8fafc")
    fig.patch.set_facecolor("#f8fafc")

    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#cbd5e1", width=2, style="dashed")
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=1800, alpha=0.9)

    labels = {n: G.nodes[n].get("label", n) for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, labels=labels, ax=ax, font_size=7, font_color="white", font_weight="bold")

    # Legend
    legend_items = [
        mpatches.Patch(color=DEVICE_COLORS["router"], label="Router / Gateway"),
        mpatches.Patch(color=DEVICE_COLORS["workstation"], label="Workstation"),
        mpatches.Patch(color=DEVICE_COLORS["laptop"], label="Laptop / Mac"),
        mpatches.Patch(color=DEVICE_COLORS["default"], label="Unknown"),
    ]
    ax.legend(handles=legend_items, loc="upper left", fontsize=9)

    mode = " (Demo Data)" if scan_results.get("demo_mode") else ""
    ax.set_title(f"Network Topology — {subnet}{mode}\nCompTIA Net+ Portfolio Project",
                 fontsize=13, pad=16, color="#1e293b")
    ax.axis("off")

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[Topology] Saved to {output_path}")
    return output_path


if __name__ == "__main__":
    # Run with demo data if called directly
    from network.scanner import _demo_scan
    demo_data = _demo_scan("192.168.1.0/24")
    build_topology(demo_data, output_path="topology_demo.png")
