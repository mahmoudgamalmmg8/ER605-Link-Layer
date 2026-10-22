"""VPN status and configuration inspection operations for ER605.

Endpoints verified against firmware:
- `/admin/ipsec?form=conn` (`method=get`) -> IPsec configured policies
- `/admin/ipsec?form=ipsec_sa` (`method=get`) -> IPsec active Security Associations (SAs)
- `/admin/openvpn?form=server_standalone` (`method=get`) -> OpenVPN servers
- `/admin/openvpn?form=client_standalone` (`method=get`) -> OpenVPN clients
- `/admin/openvpn?form=openvpn_tunnel` (`method=get`) -> Active OpenVPN tunnels
- `/admin/wireguard?form=wireguard` (`method=get`) -> WireGuard interfaces
- `/admin/wireguard?form=peers` (`method=get`) -> WireGuard peers
- `/admin/l2tp?form=server` (`method=get`) -> L2TP servers
- `/admin/l2tp?form=client` (`method=get`) -> L2TP clients
- `/admin/l2tp?form=tunnelinfo` (`method=get`) -> Active L2TP tunnels
- `/admin/pptp_server?form=server_enable` (`method=get`) -> PPTP servers
- `/admin/pptp_client?form=client_list` (`method=get`) -> PPTP clients
- `/admin/pptp_tunnel?form=pptp_tunnel` (`method=get`) -> Active PPTP tunnels
"""

from typing import Any, Dict, List

from ..client import ER605Client
from ..exceptions import ER605Error
from .system import redact_secrets


def _read_list(client: ER605Client, endpoint: str) -> List[Dict[str, Any]]:
    try:
        res = client.read(endpoint)
        if isinstance(res, list):
            return redact_secrets(res)
        if isinstance(res, dict) and res:
            return [redact_secrets(res)]
    except ER605Error:
        pass
    return []


def get_vpn_status(client: ER605Client) -> Dict[str, Any]:
    """Retrieve status and configurations across IPsec, OpenVPN, WireGuard, L2TP, and PPTP."""
    return {
        "ipsec": {
            "connections": _read_list(client, "/admin/ipsec?form=conn"),
            "active_sa": _read_list(client, "/admin/ipsec?form=ipsec_sa"),
        },
        "openvpn": {
            "servers": _read_list(client, "/admin/openvpn?form=server_standalone"),
            "clients": _read_list(client, "/admin/openvpn?form=client_standalone"),
            "active_tunnels": _read_list(client, "/admin/openvpn?form=openvpn_tunnel"),
        },
        "wireguard": {
            "interfaces": _read_list(client, "/admin/wireguard?form=wireguard"),
            "peers": _read_list(client, "/admin/wireguard?form=peers"),
        },
        "l2tp": {
            "servers": _read_list(client, "/admin/l2tp?form=server"),
            "clients": _read_list(client, "/admin/l2tp?form=client"),
            "active_tunnels": _read_list(client, "/admin/l2tp?form=tunnelinfo"),
        },
        "pptp": {
            "servers": _read_list(client, "/admin/pptp_server?form=server_enable"),
            "clients": _read_list(client, "/admin/pptp_client?form=client_list"),
            "active_tunnels": _read_list(client, "/admin/pptp_tunnel?form=pptp_tunnel"),
        },
    }
