"""Human-readable terminal table and JSON output formatters for ER605 CLI."""

import json
import urllib.parse
from typing import Any, Dict, List, Sequence

from .operations.vlan import format_vlan_ports


def format_json(data: Any) -> str:
    """Serialize structured output to indented JSON."""
    return json.dumps(data, indent=2, ensure_ascii=False)


def format_bytes(val: Any) -> str:
    """Format byte count into human-readable unit (B, KB, MB, GB, TB)."""
    try:
        num = float(val)
    except (ValueError, TypeError):
        return str(val if val is not None else "---")
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num) < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(num)} B"
            return f"{num:.2f} {unit}"
        num /= 1024.0
    return f"{num:.2f} PB"


def render_table(headers: Sequence[str], rows: Sequence[Sequence[Any]], title: str = "") -> str:
    """Render an ASCII/Unicode aligned table for terminal display."""
    str_rows = [[str(cell if cell is not None and cell != "" else "---") for cell in row] for row in rows]
    widths = [len(str(h)) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))

    lines: List[str] = []
    if title:
        lines.append(f"=== {title} ===")

    if not str_rows:
        lines.append("  (none)")
        return "\n".join(lines)

    header_line = "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
    sep_line = "  ".join("-" * widths[i] for i in range(len(headers)))
    lines.append(header_line)
    lines.append(sep_line)
    for row in str_rows:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))
    return "\n".join(lines)


def render_status(data: Dict[str, Any]) -> str:
    """Format `get_system_status` output for terminal display."""
    cpu = data.get("cpu_usage") or {}
    cpu_parts = [f"{k}: {v}%" for k, v in sorted(cpu.items()) if v is not None]
    cpu_str = ", ".join(cpu_parts) if cpu_parts else "---"
    mem = data.get("mem_usage")
    mem_str = f"{mem}%" if mem is not None else "---"

    rows = [
        ("Router Address", data.get("host")),
        ("Model", data.get("model")),
        ("Hardware Version", data.get("hardware_version")),
        ("Firmware Version", data.get("firmware_version")),
        ("System Time", data.get("system_time")),
        ("Uptime", data.get("uptime")),
        ("CPU Load", cpu_str),
        ("Memory Usage", mem_str),
        ("Config State", data.get("config_status")),
        ("HTTPS Redirect", f"{data.get('redirect_https')} (port {data.get('https_port')})"),
    ]
    return render_table(["Property", "Value"], rows, title="ER605 System Status")


def render_interfaces(data: Dict[str, Any]) -> str:
    """Format `get_interfaces_overview` output for terminal display."""
    sections: List[str] = []
    wan_mode = data.get("wan_mode") or {}
    if wan_mode:
        wan_nums = ", ".join(str(x) for x in (wan_mode.get("wan_numbers") or []))
        sections.append(
            f"WAN Mode: {wan_mode.get('wanmode', '---')} active WAN port(s) (Ports: {wan_nums or '---'})"
        )

    normal = data.get("normal_interfaces") or []
    if_rows = []
    for iface in normal:
        dns = ", ".join(
            x for x in (iface.get("dns1"), iface.get("dns2")) if x and x != "0.0.0.0"
        )
        link = "Up" if str(iface.get("t_isup")) in ("1", "true", "True") else "Down"
        if "LAN" in str(iface.get("t_name", "")).upper():
            link = "Up"
        if_rows.append([
            iface.get("t_label") or iface.get("t_name"),
            iface.get("t_name"),
            iface.get("proto") or iface.get("t_type"),
            link,
            iface.get("ipaddr") or "0.0.0.0",
            iface.get("netmask") or "0.0.0.0",
            iface.get("gateway") or "0.0.0.0",
            iface.get("macaddr") or "---",
            dns or "---",
        ])
    sections.append(
        render_table(
            ["Label", "Interface", "Proto", "Link", "IP Address", "Netmask", "Gateway", "MAC Address", "DNS"],
            if_rows,
            title="Logical Interfaces (WAN / LAN)",
        )
    )

    sw_ports = data.get("switch_ports") or []
    if sw_ports:
        sw_rows = []
        for p in sw_ports:
            sw_rows.append([
                f"Port {p.get('port')}",
                p.get("admin_state", "on"),
                p.get("state"),
                p.get("speed"),
                p.get("duplex"),
                p.get("flowcontrol"),
                p.get("negotiation_mode", "auto"),
            ])
        sections.append(
            render_table(
                ["Port", "Admin", "Link State", "Speed", "Duplex", "Flow Control", "Nego Mode"],
                sw_rows,
                title="Physical Switch Port Status",
            )
        )

    vpn_ifs = data.get("vpn_interfaces") or []
    if vpn_ifs:
        vpn_rows = [
            [v.get("t_label") or v.get("t_name"), v.get("t_type"), v.get("ipaddr"), v.get("netmask")]
            for v in vpn_ifs
        ]
        sections.append(
            render_table(["Tunnel", "Type", "IP Address", "Netmask"], vpn_rows, title="VPN Interfaces")
        )

    return "\n\n".join(sections)


def render_devices(data: Dict[str, Any]) -> str:
    """Format `get_connected_devices` output for terminal display."""
    devs = data.get("devices") or []
    rows = []
    for i, d in enumerate(devs, 1):
        rows.append([
            i,
            d.get("ipaddr"),
            d.get("mac"),
            d.get("hostname"),
            d.get("interface"),
            d.get("leasetime"),
            d.get("source"),
        ])
    header = render_table(
        ["#", "IP Address", "MAC Address", "Hostname", "Interface", "Lease Time", "Source"],
        rows,
        title=f"Connected Devices (ARP: {data.get('arp_count', 0)}, DHCP Leases: {data.get('dhcp_lease_count', 0)})",
    )
    return header


def render_dhcp_leases(leases: List[Dict[str, Any]]) -> str:
    """Format active DHCP leases for terminal display."""
    rows = []
    for i, l in enumerate(leases, 1):
        rows.append([
            i,
            l.get("name") or l.get("hostname") or "---",
            l.get("ipaddr"),
            l.get("macaddr"),
            l.get("leasetime") or l.get("expires"),
            l.get("interface") or "LAN",
        ])
    return render_table(
        ["#", "Hostname", "IP Address", "MAC Address", "Remaining Lease", "Interface"],
        rows,
        title="Active DHCP Leases",
    )


def render_dhcp_reservations(reservations: List[Dict[str, Any]]) -> str:
    """Format static DHCP reservations for terminal display."""
    rows = []
    for i, r in enumerate(reservations, 1):
        note = urllib.parse.unquote(str(r.get("note") or ""))
        rows.append([
            i,
            r.get("interface") or "LAN",
            r.get("ip"),
            r.get("mac"),
            r.get("enable"),
            r.get("bind") or "off",
            note or "---",
        ])
    return render_table(
        ["#", "Network", "IP Address", "MAC Address", "Enabled", "ARP Bind", "Description"],
        rows,
        title="DHCP Static Address Reservations",
    )


def render_dhcp_server(lan_list: List[Dict[str, Any]]) -> str:
    """Format LAN DHCP server settings for terminal display."""
    rows = []
    for net in lan_list:
        dns = ", ".join(
            x for x in (net.get("pri_dns"), net.get("snd_dns")) if x and x != "0.0.0.0"
        )
        rows.append([
            net.get("name"),
            net.get("vlanid"),
            f"{net.get('ipaddr')}/{net.get('netmask')}",
            net.get("enable"),
            f"{net.get('ipaddr_start')} - {net.get('ipaddr_end')}",
            f"{net.get('leasetime')} min",
            net.get("gateway") or net.get("ipaddr"),
            dns or "Auto",
        ])
    return render_table(
        ["Network", "VLAN", "Interface IP/Mask", "DHCP", "Address Pool", "Lease Time", "Gateway", "DNS"],
        rows,
        title="LAN Networks & DHCP Server Settings",
    )


def render_vlans(data: Dict[str, Any]) -> str:
    """Format VLANs and switch port VLAN settings for terminal display."""
    sections: List[str] = []
    vlans = data.get("vlans") or []
    v_rows = []
    for v in vlans:
        v_rows.append([
            v.get("vlan"),
            v.get("name"),
            format_vlan_ports(v.get("ports", "")),
            v.get("users") or "custom",
            urllib.parse.unquote(str(v.get("desc") or "")) or "---",
        ])
    sections.append(
        render_table(
            ["VLAN ID", "Name", "Member Ports (U=Untagged, T=Tagged)", "Used By", "Description"],
            v_rows,
            title="802.1Q VLAN Configuration",
        )
    )

    ports = data.get("ports") or []
    if ports:
        p_rows = []
        for p in ports:
            vlans_list = p.get("vlans")
            if isinstance(vlans_list, list):
                v_str = ", ".join(str(x) for x in vlans_list)
            else:
                v_str = str(vlans_list or "---")
            p_rows.append([
                f"Port {p.get('port')}",
                p.get("type"),
                p.get("pvid"),
                v_str,
            ])
        sections.append(
            render_table(
                ["Port", "Link Type", "PVID", "Member VLANs"],
                p_rows,
                title="Switch Port VLAN Assignments",
            )
        )
    return "\n\n".join(sections)


def render_routes(data: Dict[str, Any]) -> str:
    """Format routing tables for terminal display."""
    sections: List[str] = []
    sys_routes = data.get("system_routes") or []
    s_rows = []
    for i, r in enumerate(sys_routes, 1):
        s_rows.append([
            i,
            r.get("dest"),
            r.get("mask"),
            r.get("gateway"),
            r.get("metric"),
            r.get("t_label") or r.get("interface"),
        ])
    sections.append(
        render_table(
            ["#", "Destination", "Subnet Mask", "Gateway", "Metric", "Interface"],
            s_rows,
            title="Active System Routing Table",
        )
    )

    static_routes = data.get("static_routes") or []
    st_rows = []
    for i, r in enumerate(static_routes, 1):
        st_rows.append([
            i,
            r.get("name"),
            r.get("target"),
            r.get("netmask"),
            r.get("gateway"),
            r.get("t_label") or r.get("interface"),
            r.get("metric"),
            r.get("reachability") or "---",
            r.get("enable"),
        ])
    sections.append(
        render_table(
            ["#", "Name", "Destination", "Subnet Mask", "Gateway", "Interface", "Metric", "Reachability", "Enabled"],
            st_rows,
            title="Configured Static Routes",
        )
    )

    pol_routes = data.get("policy_routes") or []
    if pol_routes:
        p_rows = []
        for i, r in enumerate(pol_routes, 1):
            p_rows.append([
                i,
                r.get("name"),
                r.get("service_type"),
                r.get("src_ipgroup"),
                r.get("dst_ipgroup"),
                r.get("interfaces"),
                r.get("mode"),
                r.get("state"),
            ])
        sections.append(
            render_table(
                ["#", "Name", "Service", "Source Group", "Dest Group", "WAN Interface", "Mode", "Status"],
                p_rows,
                title="Policy Routing Rules",
            )
        )
    return "\n\n".join(sections)


def render_firewall(data: Dict[str, Any]) -> str:
    """Format firewall, ACL, attack defense, MAC filtering, IP-MAC binding, and NAT rules."""
    sections: List[str] = []

    acl = data.get("acl_rules") or []
    acl_rows = []
    for i, r in enumerate(acl, 1):
        zones = r.get("zone")
        if isinstance(zones, list):
            z_str = ",".join(str(z) for z in zones)
        else:
            z_str = str(zones or "---")
        src = r.get("srcIf") if z_str == "VNET" else r.get("src")
        dst = r.get("destIf") if z_str == "VNET" else r.get("dest")
        acl_rows.append([
            i,
            r.get("name"),
            r.get("policy"),
            r.get("service"),
            z_str,
            src,
            dst,
            r.get("time"),
        ])
    sections.append(
        render_table(
            ["#", "Rule Name", "Policy", "Service", "Zone/Direction", "Source", "Destination", "Schedule"],
            acl_rows,
            title="Access Control (ACL) Rules",
        )
    )

    defense = data.get("attack_defense") or {}
    dos = defense.get("dos_defense") or {}
    flood = defense.get("flood_defense") or {}
    if dos or flood:
        def_rows = []
        for k in ("tcp_conn_en", "udp_conn_en", "icmp_conn_en", "tcp_src_en", "udp_src_en", "icmp_src_en"):
            if k in flood:
                lim_key = k.replace("_en", "_lim")
                def_rows.append([f"Flood: {k}", f"{flood.get(k)} (limit: {flood.get(lim_key, '---')})"])
        for k in ("tcp_noflag", "tcp_scan_reject", "ping_death", "ping_large", "ping_wan", "tcp_winnuke", "tcp_fin_syn", "tcp_fin_noack"):
            if k in dos:
                def_rows.append([f"Packet Defense: {k}", dos.get(k)])
        sections.append(render_table(["Defense Check", "Status"], def_rows, title="Attack & DoS Defense"))

    mac_f = data.get("mac_filtering") or {}
    mac_set = mac_f.get("settings") or {}
    mac_rules = mac_f.get("rules") or []
    m_title = f"MAC Filtering (Enabled: {mac_set.get('enable', 'off')}, Mode: {mac_set.get('filter_mode', '---')})"
    m_rows = [[i, r.get("name"), r.get("mac")] for i, r in enumerate(mac_rules, 1)]
    sections.append(render_table(["#", "Name", "MAC Address"], m_rows, title=m_title))

    imb = data.get("ip_mac_binding") or {}
    imb_set = imb.get("settings") or {}
    imb_list = imb.get("bindings") or []
    imb_title = f"IP-MAC Binding (ARP Defense Enabled: {imb_set.get('enable', 'off')})"
    imb_rows = [
        [i, b.get("ipaddr"), b.get("mac"), b.get("t_label") or b.get("zone"), b.get("enable"), b.get("note") or "---"]
        for i, b in enumerate(imb_list, 1)
    ]
    sections.append(
        render_table(["#", "IP Address", "MAC Address", "Interface", "Enabled", "Description"], imb_rows, title=imb_title)
    )

    nat = data.get("nat") or {}
    vs = nat.get("virtual_servers") or []
    if vs:
        vs_rows = [
            [i, v.get("name"), v.get("t_label") or v.get("interface"), v.get("external_port"), v.get("internal_port"), v.get("ipaddr"), v.get("protocol"), v.get("enable")]
            for i, v in enumerate(vs, 1)
        ]
        sections.append(
            render_table(
                ["#", "Name", "Interface", "Ext Port", "Int Port", "Internal IP", "Proto", "Enabled"],
                vs_rows,
                title="NAT Virtual Servers (Port Forwarding)",
            )
        )

    return "\n\n".join(sections)


def render_vpn_status(data: Dict[str, Any]) -> str:
    """Format VPN configurations and active tunnels across IPsec, OpenVPN, WireGuard, L2TP, and PPTP."""
    sections: List[str] = []

    ipsec = data.get("ipsec") or {}
    conns = ipsec.get("connections") or []
    c_rows = [
        [i, c.get("name"), c.get("remote_peer"), c.get("local_binding"), c.get("local_network"), c.get("remote_network"), c.get("status")]
        for i, c in enumerate(conns, 1)
    ]
    sections.append(
        render_table(
            ["#", "Policy Name", "Remote Gateway", "WAN", "Local Subnet", "Remote Subnet", "Status"],
            c_rows,
            title="IPsec VPN Policies",
        )
    )
    sa_list = ipsec.get("active_sa") or []
    sa_rows = [
        [i, s.get("name"), s.get("spi"), s.get("direction"), s.get("tunnel"), s.get("flows"), s.get("encapsule")]
        for i, s in enumerate(sa_list, 1)
    ]
    sections.append(
        render_table(
            ["#", "Name", "SPI", "Direction", "Tunnel Endpoints", "Traffic Flows", "Protocol"],
            sa_rows,
            title="Active IPsec Security Associations (SA)",
        )
    )

    ovpn = data.get("openvpn") or {}
    ovpn_srv = ovpn.get("servers") or []
    os_rows = [
        [i, s.get("name") or s.get("cname"), s.get("proto"), s.get("port"), s.get("ippool"), s.get("local_network"), s.get("enabled")]
        for i, s in enumerate(ovpn_srv, 1)
    ]
    sections.append(
        render_table(["#", "Name", "Proto", "Port", "VPN Pool", "Local Network", "Enabled"], os_rows, title="OpenVPN Servers")
    )
    ovpn_tun = ovpn.get("active_tunnels") or []
    if ovpn_tun:
        ot_rows = [
            [i, t.get("name"), t.get("username"), t.get("remoteIp"), t.get("localIp"), format_bytes(t.get("downbytes")), format_bytes(t.get("upbytes")), t.get("uptime")]
            for i, t in enumerate(ovpn_tun, 1)
        ]
        sections.append(
            render_table(["#", "Server/Client", "User", "Remote IP", "Virtual IP", "RX", "TX", "Uptime"], ot_rows, title="Active OpenVPN Tunnels")
        )

    wg = data.get("wireguard") or {}
    wg_ifs = wg.get("interfaces") or []
    wg_rows = [
        [i, w.get("name"), w.get("listen_port"), w.get("ipaddr"), w.get("public_key"), w.get("status")]
        for i, w in enumerate(wg_ifs, 1)
    ]
    sections.append(
        render_table(["#", "Interface", "Listen Port", "Local IP", "Public Key", "Status"], wg_rows, title="WireGuard VPN Interfaces")
    )

    l2tp = data.get("l2tp") or {}
    l2tp_tun = l2tp.get("active_tunnels") or []
    l2_rows = [
        [i, t.get("username") or t.get("tunnelname"), t.get("isserver"), t.get("remoteip"), t.get("remotepppip"), t.get("uptime")]
        for i, t in enumerate(l2tp_tun, 1)
    ]
    sections.append(
        render_table(["#", "User / Tunnel", "Server?", "Remote IP", "Virtual PPP IP", "Uptime"], l2_rows, title="Active L2TP Tunnels")
    )

    pptp = data.get("pptp") or {}
    pptp_tun = pptp.get("active_tunnels") or []
    pp_rows = [
        [i, t.get("username") or t.get("name"), t.get("isserver"), t.get("remotepppip"), t.get("ifname"), t.get("uptime")]
        for i, t in enumerate(pptp_tun, 1)
    ]
    sections.append(
        render_table(["#", "User / Tunnel", "Server?", "Remote PPP IP", "Interface", "Uptime"], pp_rows, title="Active PPTP Tunnels")
    )

    return "\n\n".join(sections)


def render_traffic(data: Dict[str, Any]) -> str:
    """Format interface traffic, per-IP traffic, and switch port counters."""
    sections: List[str] = []

    if_stats = data.get("interfaces") or []
    if_rows = []
    for s in if_stats:
        if_rows.append([
            s.get("interface") or s.get("zone"),
            format_bytes(s.get("rx_bytes")),
            s.get("rx_pkts"),
            format_bytes(s.get("tx_bytes")),
            s.get("tx_pkts"),
            f"{format_bytes(s.get('rx_bps'))}/s",
            f"{format_bytes(s.get('tx_bps'))}/s",
        ])
    sections.append(
        render_table(
            ["Interface", "RX Bytes", "RX Packets", "TX Bytes", "TX Packets", "RX Rate", "TX Rate"],
            if_rows,
            title="Interface Traffic Statistics",
        )
    )

    ip_stats = data.get("ip_stats") or {}
    ip_set = ip_stats.get("setting") or {}
    ip_entries = ip_stats.get("entries") or []
    ip_rows = []
    for e in ip_entries[:30]:
        ip_rows.append([
            e.get("addr"),
            format_bytes(e.get("rx_bytes")),
            e.get("rx_pkts"),
            format_bytes(e.get("tx_bytes")),
            e.get("tx_pkts"),
            f"{format_bytes(e.get('rx_bps'))}/s",
            f"{format_bytes(e.get('tx_bps'))}/s",
        ])
    sections.append(
        render_table(
            ["IP Address", "RX Bytes", "RX Packets", "TX Bytes", "TX Packets", "RX Rate", "TX Rate"],
            ip_rows,
            title=f"Per-IP Traffic Statistics (Enabled: {ip_set.get('status', 'off')})",
        )
    )

    sw_stats = data.get("switch_ports") or []
    if sw_stats:
        sw_rows = []
        for p in sw_stats:
            sw_rows.append([
                f"Port {p.get('port')}",
                p.get("rx_All") or p.get("rx_Normal"),
                p.get("rx_Unicast", "---"),
                p.get("rx_Broad", "---"),
                p.get("tx_All") or p.get("tx_Normal"),
                p.get("tx_Unicast", "---"),
                p.get("tx_Broad", "---"),
            ])
        sections.append(
            render_table(
                ["Port", "RX Total Pkts", "RX Unicast", "RX Broadcast", "TX Total Pkts", "TX Unicast", "TX Broadcast"],
                sw_rows,
                title="Switch Port Packet Statistics",
            )
        )

    return "\n\n".join(sections)


def render_logs(data: Dict[str, Any]) -> str:
    """Format system logs for terminal display."""
    logs = data.get("logs") or []
    rows = []
    for l in logs:
        rows.append([
            l.get("key"),
            l.get("time"),
            l.get("type"),
            l.get("level"),
            l.get("content"),
        ])
    return render_table(
        ["#", "Timestamp", "Module", "Severity", "Message"],
        rows,
        title=f"System Logs (Page {data.get('page_num', 1)}, Total: {data.get('total_log', len(logs))})",
    )
