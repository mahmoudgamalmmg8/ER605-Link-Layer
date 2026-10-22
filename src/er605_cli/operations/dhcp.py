"""Connected devices, ARP table, DHCP leases, DHCP reservations, and LAN DHCP settings for ER605.

Endpoints verified against firmware:
- `/admin/arplist?form=getlist` (`method=get`) -> ARP table (`ipaddr`, `mac`, `interface`, `zone`, `status`)
- `/admin/dhcps?form=client` (`method=get`) -> Active DHCP leases (`name`/`hostname`, `ipaddr`, `macaddr`, `leasetime`, `interface`)
- `/admin/dhcps?form=reservation` (`method=get|add|set|delete`) -> Static DHCP reservations (`interface`, `mac`, `ip`, `note`, `enable`, `bind`)
- `/admin/dhcps?form=lan` (`method=get|add|set|delete`) -> LAN network & DHCP server settings
- `/admin/imb?form=bind_list` (`method=get|add|set|delete`) -> IP-MAC binding entries
- `/admin/imb?form=enable` (`method=get|set`) -> ARP defense / IP-MAC binding enforcement settings
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional

from ..client import ER605Client
from ..exceptions import ER605Error, ValidationError

MAC_REGEX = re.compile(r"^[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}$")


def normalize_mac(mac: str) -> str:
    """Validate a unicast MAC address and normalize it to uppercase hyphen-separated (`AA-BB-CC-DD-EE-FF`)."""
    mac_str = str(mac or "").strip()
    if not MAC_REGEX.match(mac_str):
        raise ValidationError(
            f"Invalid MAC address '{mac}'. Expected format XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX."
        )
    normalized = mac_str.replace(":", "-").upper()
    if normalized == "00-00-00-00-00-00" or normalized == "FF-FF-FF-FF-FF-FF":
        raise ValidationError(f"MAC address '{normalized}' cannot be all-zeros or broadcast.")
    first_octet = int(normalized.split("-")[0], 16)
    if first_octet & 1:
        raise ValidationError(f"MAC address '{normalized}' is a multicast address; unicast MAC required.")
    return normalized


def validate_ipv4(ip_str: str, field_name: str = "IP address") -> str:
    """Validate an IPv4 address string."""
    val = str(ip_str or "").strip()
    try:
        ip_obj = ipaddress.IPv4Address(val)
    except ValueError as exc:
        raise ValidationError(f"Invalid {field_name}: '{ip_str}'.") from exc
    return str(ip_obj)


def get_arp_list(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve router ARP table via `/admin/arplist?form=getlist`."""
    res = client.read("/admin/arplist?form=getlist")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and res:
        return [res]
    return []


def get_dhcp_leases(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve active DHCP client leases via `/admin/dhcps?form=client`."""
    res = client.read("/admin/dhcps?form=client")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and res:
        return [res]
    return []


def get_dhcp_reservations(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve static DHCP address reservations via `/admin/dhcps?form=reservation`."""
    res = client.read("/admin/dhcps?form=reservation")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and res:
        return [res]
    return []


def get_lan_dhcp_settings(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve LAN network and DHCP server settings via `/admin/dhcps?form=lan`."""
    res = client.read("/admin/dhcps?form=lan")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and res:
        return [res]
    return []


def get_connected_devices(client: ER605Client) -> Dict[str, Any]:
    """Correlate ARP table entries and active DHCP leases into a unified connected devices list."""
    arp_entries = get_arp_list(client)
    leases: List[Dict[str, Any]] = []
    try:
        leases = get_dhcp_leases(client)
    except ER605Error:
        pass

    by_key: Dict[str, Dict[str, Any]] = {}

    for lease in leases:
        ip = str(lease.get("ipaddr", "")).strip()
        mac = str(lease.get("macaddr", "")).strip().replace(":", "-").upper()
        key = ip or mac
        if not key:
            continue
        by_key[key] = {
            "ipaddr": ip,
            "mac": mac,
            "hostname": lease.get("name") or lease.get("hostname") or "---",
            "interface": lease.get("interface") or "LAN",
            "leasetime": lease.get("leasetime") or "---",
            "arp_status": "---",
            "source": "DHCP",
        }

    for arp in arp_entries:
        ip = str(arp.get("ipaddr", "")).strip()
        mac = str(arp.get("mac", "")).strip().replace(":", "-").upper()
        key = ip or mac
        if not key:
            continue
        if key in by_key:
            by_key[key]["arp_status"] = arp.get("status", "reachable")
            by_key[key]["interface"] = arp.get("t_label") or arp.get("interface") or arp.get("zone") or by_key[key]["interface"]
            by_key[key]["source"] = "DHCP+ARP"
            if not by_key[key]["mac"] and mac:
                by_key[key]["mac"] = mac
        else:
            by_key[key] = {
                "ipaddr": ip,
                "mac": mac,
                "hostname": "---",
                "interface": arp.get("t_label") or arp.get("interface") or arp.get("zone") or "LAN",
                "leasetime": "---",
                "arp_status": arp.get("status", "---"),
                "source": "ARP",
            }

    devices = sorted(
        by_key.values(),
        key=lambda d: tuple(int(x) for x in d["ipaddr"].split("."))
        if d.get("ipaddr") and all(p.isdigit() for p in d["ipaddr"].split(".")) and len(d["ipaddr"].split(".")) == 4
        else (999, 999, 999, 999),
    )

    return {
        "devices": devices,
        "arp_count": len(arp_entries),
        "dhcp_lease_count": len(leases),
    }


def add_dhcp_reservation(
    client: ER605Client,
    ip: str,
    mac: str,
    interface: str = "LAN",
    note: str = "",
    enable: str = "on",
    bind: str = "off",
) -> Any:
    """Create a static DHCP reservation via `/admin/dhcps?form=reservation` (`method=add`).

    Matches `dhcp_static.html` store.insert payload:
    `{"method":"add","params":{"index":0,"new":{"interface":...,"mac":...,"ip":...,"note":...,"enable":...,"bind":...},"ip":"add"}}`
    """
    valid_ip = validate_ipv4(ip, "reservation IP")
    valid_mac = normalize_mac(mac)
    en_val = "on" if str(enable).lower() in ("on", "true", "1", "yes", "enable") else "off"
    bind_val = "on" if str(bind).lower() in ("on", "true", "1", "yes", "enable") else "off"

    existing = get_dhcp_reservations(client)
    for item in existing:
        if item.get("ip") == valid_ip:
            raise ValidationError(f"A DHCP reservation for IP {valid_ip} already exists.")
        if str(item.get("mac", "")).upper() == valid_mac and item.get("interface") == interface:
            raise ValidationError(f"A DHCP reservation for MAC {valid_mac} on {interface} already exists.")

    new_entry = {
        "interface": interface,
        "mac": valid_mac,
        "ip": valid_ip,
        "note": note,
        "enable": en_val,
        "bind": bind_val,
    }
    return client.write(
        "/admin/dhcps?form=reservation",
        method="add",
        params={
            "index": len(existing),
            "new": new_entry,
            "ip": "add",
        },
    )


def update_dhcp_reservation(
    client: ER605Client,
    target_ip: str,
    new_ip: Optional[str] = None,
    new_mac: Optional[str] = None,
    interface: Optional[str] = None,
    note: Optional[str] = None,
    enable: Optional[str] = None,
    bind: Optional[str] = None,
) -> Any:
    """Update an existing DHCP reservation via `/admin/dhcps?form=reservation` (`method=set`)."""
    valid_target_ip = validate_ipv4(target_ip, "target reservation IP")
    existing = get_dhcp_reservations(client)

    idx = None
    old_entry = None
    for i, item in enumerate(existing):
        if item.get("ip") == valid_target_ip:
            idx = i
            old_entry = item
            break

    if idx is None or old_entry is None:
        raise ValidationError(f"DHCP reservation for IP '{valid_target_ip}' not found.")

    old_clean = {
        "interface": old_entry.get("interface", "LAN"),
        "mac": old_entry.get("mac", ""),
        "ip": old_entry.get("ip", valid_target_ip),
        "note": old_entry.get("note", ""),
        "enable": old_entry.get("enable", "on"),
        "bind": old_entry.get("bind", "off"),
    }
    updated = dict(old_clean)
    if new_ip is not None:
        updated["ip"] = validate_ipv4(new_ip, "new IP")
    if new_mac is not None:
        updated["mac"] = normalize_mac(new_mac)
    if interface is not None:
        updated["interface"] = interface
    if note is not None:
        updated["note"] = note
    if enable is not None:
        updated["enable"] = "on" if str(enable).lower() in ("on", "true", "1", "yes", "enable") else "off"
    if bind is not None:
        updated["bind"] = "on" if str(bind).lower() in ("on", "true", "1", "yes", "enable") else "off"

    return client.write(
        "/admin/dhcps?form=reservation",
        method="set",
        params={
            "index": idx,
            "old": old_clean,
            "new": updated,
            "ip": valid_target_ip,
        },
    )


def delete_dhcp_reservation(client: ER605Client, target_ip: str) -> Any:
    """Remove a DHCP reservation by IP address via `/admin/dhcps?form=reservation` (`method=delete`).

    Note: `dhcp_static.html` configures `keyProperty: "ip"` and `extraProperty: "interface"`.
    """
    valid_target_ip = validate_ipv4(target_ip, "reservation IP")
    existing = get_dhcp_reservations(client)

    idx = None
    matched = None
    for i, item in enumerate(existing):
        if item.get("ip") == valid_target_ip:
            idx = i
            matched = item
            break

    if idx is None or matched is None:
        raise ValidationError(f"DHCP reservation for IP '{valid_target_ip}' not found.")

    return client.write(
        "/admin/dhcps?form=reservation",
        method="delete",
        params={
            "key": str(matched.get("key") or valid_target_ip),
            "index": str(idx),
            "extraKey": str(matched.get("interface", "LAN")),
        },
    )
