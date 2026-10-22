"""Firewall, Access Control (ACL), Attack Defense, MAC Filtering, IP-MAC Binding, and NAT operations for ER605.

Endpoints verified against firmware:
- `/admin/access_ctl?form=acl_inner` (`method=get|add|set|delete`) -> Access Control rules
- `/admin/dos_defense?form=settings` (`method=get|set`) -> Packet anomaly defense settings
- `/admin/flood_defense?form=settings` (`method=get|set`) -> SYN/UDP/ICMP flood defense settings
- `/admin/mac_filter?form=mode` (`method=get|set`) -> MAC filtering global mode (`enable`, `filter_mode`, `interfaces`)
- `/admin/mac_filter?form=mac_list` (`method=get|add|set|delete`) -> MAC filter rules (`name`, `mac`)
- `/admin/imb?form=enable` (`method=get|set`) -> ARP defense / IP-MAC binding settings
- `/admin/imb?form=bind_list` (`method=get|add|set|delete`) -> IP-MAC binding entries
- `/admin/nat?form=vs` (`method=get|add|set|delete`) -> Virtual Server (port forwarding) rules
- `/admin/nat?form=napt` (`method=get`) -> Multi-nets NAT rules
- `/admin/nat?form=dmz` (`method=get`) -> DMZ rules
- `/admin/nat?form=alg` (`method=get`) -> NAT ALG settings
"""

from typing import Any, Dict, List, Optional, Sequence

from ..client import ER605Client
from ..exceptions import ER605Error, ValidationError
from .dhcp import normalize_mac


def get_acl_rules(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve Access Control (ACL) rules via `/admin/access_ctl?form=acl_inner`."""
    res = client.read("/admin/access_ctl?form=acl_inner")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and res:
        return [res]
    return []


def get_attack_defense(client: ER605Client) -> Dict[str, Any]:
    """Retrieve DoS / Packet defense and Flood defense settings."""
    dos = {}
    flood = {}
    try:
        res = client.read("/admin/dos_defense?form=settings")
        if isinstance(res, dict):
            dos = res
    except ER605Error:
        pass
    try:
        res = client.read("/admin/flood_defense?form=settings")
        if isinstance(res, dict):
            flood = res
    except ER605Error:
        pass
    return {"dos_defense": dos, "flood_defense": flood}


def get_mac_filtering(client: ER605Client) -> Dict[str, Any]:
    """Retrieve MAC filtering global settings and rule list."""
    mode = {}
    rules: List[Dict[str, Any]] = []
    try:
        m_res = client.read("/admin/mac_filter?form=mode")
        if isinstance(m_res, dict):
            mode = m_res
    except ER605Error:
        pass
    try:
        r_res = client.read("/admin/mac_filter?form=mac_list")
        if isinstance(r_res, list):
            rules = r_res
        elif isinstance(r_res, dict) and r_res:
            rules = [r_res]
    except ER605Error:
        pass
    return {"settings": mode, "rules": rules}


def get_ip_mac_binding(client: ER605Client) -> Dict[str, Any]:
    """Retrieve IP-MAC binding / ARP defense settings and binding list."""
    settings = {}
    bindings: List[Dict[str, Any]] = []
    try:
        s_res = client.read("/admin/imb?form=enable")
        if isinstance(s_res, dict):
            settings = s_res
    except ER605Error:
        pass
    try:
        b_res = client.read("/admin/imb?form=bind_list")
        if isinstance(b_res, list):
            bindings = b_res
        elif isinstance(b_res, dict) and b_res:
            bindings = [b_res]
    except ER605Error:
        pass
    return {"settings": settings, "bindings": bindings}


def get_nat_rules(client: ER605Client) -> Dict[str, Any]:
    """Retrieve Virtual Server (port forwarding), NAPT, DMZ, and ALG settings."""
    out: Dict[str, Any] = {
        "virtual_servers": [],
        "napt": [],
        "dmz": [],
        "alg": {},
    }
    for key, ep in [
        ("virtual_servers", "/admin/nat?form=vs"),
        ("napt", "/admin/nat?form=napt"),
        ("dmz", "/admin/nat?form=dmz"),
    ]:
        try:
            res = client.read(ep)
            if isinstance(res, list):
                out[key] = res
            elif isinstance(res, dict) and res:
                out[key] = [res]
        except ER605Error:
            pass
    try:
        alg_res = client.read("/admin/nat?form=alg")
        if isinstance(alg_res, dict):
            out["alg"] = alg_res
    except ER605Error:
        pass
    return out


def get_firewall_overview(client: ER605Client) -> Dict[str, Any]:
    """Retrieve comprehensive firewall overview: ACL rules, Attack Defense, MAC Filtering, IP-MAC Binding, and NAT."""
    acl = get_acl_rules(client)
    defense = get_attack_defense(client)
    mac_f = get_mac_filtering(client)
    imb = get_ip_mac_binding(client)
    nat = get_nat_rules(client)
    return {
        "acl_rules": acl,
        "attack_defense": defense,
        "mac_filtering": mac_f,
        "ip_mac_binding": imb,
        "nat": nat,
    }


def add_acl_rule(
    client: ER605Client,
    name: str,
    policy: str = "DROP",
    service: str = "ALL",
    zones: Sequence[str] = ("LAN",),
    src: str = "IPGROUP_ANY",
    dest: str = "IPGROUP_ANY",
    src_if: str = "LAN",
    dest_if: str = "LAN",
    time_obj: str = "Any",
    position: Optional[int] = None,
) -> Any:
    """Create an Access Control (ACL) rule via `/admin/access_ctl?form=acl_inner` (`method=add`).

    Matches `access_control.html` and `access_ctl.lua` (`acl_inner_add_rule`).
    """
    clean_name = str(name or "").strip()
    if not clean_name or len(clean_name) > 50:
        raise ValidationError("ACL rule name must be 1..50 characters.")

    pol = str(policy or "").strip().upper()
    if pol not in ("ACCEPT", "DROP"):
        raise ValidationError("ACL policy must be 'ACCEPT' or 'DROP'.")

    zone_list = [str(z).strip() for z in zones if str(z).strip()]
    if not zone_list:
        raise ValidationError("At least one zone (e.g. 'LAN', 'WAN1', 'VNET', 'ALL') is required.")

    existing = get_acl_rules(client)
    for r in existing:
        if r.get("name") == clean_name:
            raise ValidationError(f"ACL rule '{clean_name}' already exists.")

    states = ["new", "established", "related"]
    if pol != "ACCEPT":
        states.append("invalid")

    new_obj: Dict[str, Any] = {
        "name": clean_name,
        "policy": pol,
        "service": service,
        "zone": zone_list if len(zone_list) > 1 else zone_list[0],
        "time": time_obj,
        "states": states,
        "position": str(position) if position is not None else "",
    }
    if "VNET" in zone_list:
        new_obj["srcIf"] = src_if
        new_obj["destIf"] = dest_if
    else:
        new_obj["src"] = src
        new_obj["dest"] = dest

    return client.write(
        "/admin/access_ctl?form=acl_inner",
        method="add",
        params={
            "index": len(existing),
            "old": "add",
            "new": new_obj,
            "key": "add",
        },
    )


def delete_acl_rule(client: ER605Client, name_or_key: str) -> Any:
    """Delete an Access Control (ACL) rule by name or key via `/admin/access_ctl?form=acl_inner` (`method=delete`)."""
    ident = str(name_or_key or "").strip()
    existing = get_acl_rules(client)
    idx = None
    matched = None
    for i, r in enumerate(existing):
        if r.get("name") == ident or str(r.get("key")) == ident:
            idx = i
            matched = r
            break

    if idx is None or matched is None:
        raise ValidationError(f"ACL rule '{ident}' not found.")

    if str(matched.get("user")) == "0":
        raise ValidationError(f"ACL rule '{ident}' is a system rule and cannot be deleted.")

    key_val = str(matched.get("key") or f"key-{idx}")
    return client.write(
        "/admin/access_ctl?form=acl_inner",
        method="delete",
        params={
            "key": key_val,
            "index": str(idx),
        },
    )


def set_mac_filtering_mode(
    client: ER605Client,
    enable: str = "on",
    filter_mode: str = "black",
    interfaces: str = "WAN",
) -> Any:
    """Configure global MAC filtering mode via `/admin/mac_filter?form=mode` (`method=set`).

    Verified against `www/webpages/pages/userrpm/macFiltering.html`:
    - `enable`: `'on'` or `'off'`
    - `filter_mode`: `'black'` (deny listed MACs) or `'white'` (allow only listed MACs)
    - `interfaces`: `'WAN'` (LAN->WAN traffic) or `'ALL'` (all router traffic)
    """
    en_val = "on" if str(enable).lower() in ("on", "true", "1", "yes", "enable") else "off"
    mode_val = str(filter_mode or "black").lower().strip()
    if mode_val in ("deny", "block", "blacklist"):
        mode_val = "black"
    elif mode_val in ("allow", "whitelist"):
        mode_val = "white"
    if mode_val not in ("black", "white"):
        raise ValidationError("MAC filter mode must be 'black' (deny list) or 'white' (allow list).")

    iface_val = str(interfaces or "WAN").upper().strip()
    if iface_val not in ("WAN", "ALL"):
        raise ValidationError("MAC filter zone (--zone) must be 'WAN' (LAN->WAN) or 'ALL'.")

    return client.write(
        "/admin/mac_filter?form=mode",
        method="set",
        params={
            "enable": en_val,
            "filter_mode": mode_val,
            "interfaces": iface_val,
        },
    )


def add_mac_filter_rule(client: ER605Client, name: str, mac: str) -> Any:
    """Add a MAC filtering rule via `/admin/mac_filter?form=mac_list` (`method=add`)."""
    clean_name = str(name or "").strip()
    if not clean_name or len(clean_name) > 50:
        raise ValidationError("MAC filter rule name must be 1..50 characters.")
    valid_mac = normalize_mac(mac)

    existing = get_mac_filtering(client)["rules"]
    for r in existing:
        if r.get("name") == clean_name:
            raise ValidationError(f"MAC filter rule named '{clean_name}' already exists.")
        if str(r.get("mac", "")).upper() == valid_mac:
            raise ValidationError(f"MAC address '{valid_mac}' is already in the MAC filter list.")

    return client.write(
        "/admin/mac_filter?form=mac_list",
        method="add",
        params={
            "index": len(existing),
            "old": "add",
            "new": {"name": clean_name, "mac": valid_mac},
            "key": "add",
        },
    )


def delete_mac_filter_rule(client: ER605Client, name_or_mac: str) -> Any:
    """Delete a MAC filtering rule by name, MAC address, or key via `/admin/mac_filter?form=mac_list` (`method=delete`)."""
    ident = str(name_or_mac or "").strip()
    norm_ident = ident.replace(":", "-").upper()
    existing = get_mac_filtering(client)["rules"]
    idx = None
    matched = None
    for i, r in enumerate(existing):
        if (
            r.get("name") == ident
            or str(r.get("key")) == ident
            or str(r.get("mac", "")).upper() == norm_ident
        ):
            idx = i
            matched = r
            break

    if idx is None or matched is None:
        raise ValidationError(f"MAC filter rule '{ident}' not found.")

    key_val = str(matched.get("key") or f"key-{idx}")
    return client.write(
        "/admin/mac_filter?form=mac_list",
        method="delete",
        params={
            "key": key_val,
            "index": str(idx),
        },
    )
