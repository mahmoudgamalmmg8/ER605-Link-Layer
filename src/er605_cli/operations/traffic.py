"""Interface and per-IP traffic statistics operations for ER605.

Endpoints verified against firmware (`ifstat.lua`, `ipstats.lua`, `switch.lua`):
- `/admin/ifstat?form=list` (`method=get|clear`) -> interface traffic statistics (`interface`, `zone`, `rx_bytes`, `rx_pkts`, `tx_bytes`, `tx_pkts`, `rx_bps`, `rx_pps`, `tx_bps`, `tx_pps`)
- `/admin/ipstats?form=setting` (`method=get|set`) -> IP traffic statistics enable/status
- `/admin/ipstats?form=list` (`method=get|clear`) -> per-IP traffic statistics (`addr`, `rx_bytes`, `rx_pkts`, `tx_bytes`, `tx_pkts`, `rx_bps`, `rx_pps`, `tx_bps`, `tx_pps`)
- `/admin/switch?form=statistic` (`method=get`) -> physical switch port packet statistics
"""

from typing import Any, Dict, List

from ..client import ER605Client
from ..exceptions import ER605Error


def get_interface_traffic(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve logical interface traffic statistics via `/admin/ifstat?form=list`."""
    res = client.read("/admin/ifstat?form=list")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and res:
        return [res]
    return []


def get_ip_traffic(client: ER605Client) -> Dict[str, Any]:
    """Retrieve per-host IP traffic statistics settings and list via `/admin/ipstats`."""
    setting = {}
    entries: List[Dict[str, Any]] = []
    try:
        s_res = client.read("/admin/ipstats?form=setting")
        if isinstance(s_res, dict):
            setting = s_res
    except ER605Error:
        pass
    try:
        l_res = client.read("/admin/ipstats?form=list")
        if isinstance(l_res, list):
            entries = l_res
        elif isinstance(l_res, dict) and l_res:
            entries = [l_res]
    except ER605Error:
        pass
    return {"setting": setting, "entries": entries}


def get_switch_traffic(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve physical switch port packet counters via `/admin/switch?form=statistic`."""
    try:
        res = client.read("/admin/switch?form=statistic")
        if isinstance(res, list):
            return res
        if isinstance(res, dict) and res:
            return [res]
    except ER605Error:
        pass
    return []


def get_traffic_overview(client: ER605Client) -> Dict[str, Any]:
    """Retrieve combined interface traffic, per-IP traffic, and switch port statistics."""
    if_stats = get_interface_traffic(client)
    ip_stats = get_ip_traffic(client)
    sw_stats = get_switch_traffic(client)
    return {
        "interfaces": if_stats,
        "ip_stats": ip_stats,
        "switch_ports": sw_stats,
    }
