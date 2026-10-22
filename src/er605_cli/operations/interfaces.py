"""WAN/LAN interface, physical switch port control, and WAN connect/disconnect operations for ER605.

Endpoints verified against firmware:
- `/admin/interface?form=status2` (`method=get`) -> `normal` (WAN1..4, LAN) and `vpn` interfaces
- `/admin/interface?form=status` (`method=get`) -> basic interface list
- `/admin/interface_wan?form=wanmode` (`method=get`) -> active WAN count, `wan_numbers`, `wan_names`
- `/admin/switch?form=state` (`method=get`) -> physical switch port state, speed, duplex, flowcontrol
- `/admin/switch?form=para` (`method=get|set`) -> physical switch port admin state (`on|off`), flowcontrol, negotiation_mode
- `/admin/switch?form=statistic` (`method=get`) -> per-port switch RX/TX packet counters
- `/admin/interface_wan?form=connect` (`method=set`, `params={"wan_id": "<1..4>"}`)
- `/admin/interface_wan?form=disconnect` (`method=set`, `params={"wan_id": "<1..4>"}`)
"""

from typing import Any, Dict, List, Optional

from ..client import ER605Client
from ..exceptions import ER605Error, ValidationError

VALID_NEGOTIATION_MODES = ("auto", "10MH", "10MF", "100MH", "100MF", "1000MF")


def get_switch_port_params(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve physical switch port parameters (`port_state`, `flowcontrol`, `negotiation_mode`) via `/admin/switch?form=para`."""
    res = client.read("/admin/switch?form=para")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and res:
        return [res]
    return []


def set_switch_port_params(
    client: ER605Client,
    port: int,
    state: Optional[str] = None,
    flowcontrol: Optional[str] = None,
    negotiation_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Enable/disable a physical RJ45 switch port (1..5) or change its speed/flowcontrol via `/admin/switch?form=para`.

    In the ER605 firmware (`lib/switch/mt7621_switch_portPara`), setting `state="off"` sets
    IEEE 802.3 PHY Control Register bit 11 (Power Down) on the MT7530 switch port, physically
    taking the link down even though TP-Link hid the checkbox in `switch_Parameter.html`.
    """
    try:
        port_num = int(port)
    except (ValueError, TypeError) as exc:
        raise ValidationError("Switch port must be an integer between 1 and 5.") from exc
    if not (1 <= port_num <= 5):
        raise ValidationError("Switch port must be between 1 and 5.")

    current_list = get_switch_port_params(client)
    if not current_list:
        current_list = [
            {"port": str(p), "port_state": "on", "flowcontrol": "off", "negotiation_mode": "auto"}
            for p in range(1, 6)
        ]

    payload_list: List[Dict[str, str]] = []
    updated_item: Optional[Dict[str, str]] = None

    for item in current_list:
        p_str = str(item.get("port", ""))
        cur_state = str(item.get("port_state") or item.get("state") or "on")
        cur_fc = str(item.get("flowcontrol") or "off")
        cur_mode = str(item.get("negotiation_mode") or "auto")

        if p_str == str(port_num):
            if state is not None:
                cur_state = "on" if str(state).lower() in ("on", "true", "1", "yes", "enable", "up") else "off"
            if flowcontrol is not None:
                cur_fc = "on" if str(flowcontrol).lower() in ("on", "true", "1", "yes", "enable") else "off"
            if negotiation_mode is not None:
                norm_mode = str(negotiation_mode).strip()
                if norm_mode.lower() == "auto":
                    norm_mode = "auto"
                else:
                    norm_mode = norm_mode.upper()
                if norm_mode not in VALID_NEGOTIATION_MODES:
                    raise ValidationError(
                        f"Invalid negotiation mode '{negotiation_mode}'. Valid modes: {', '.join(VALID_NEGOTIATION_MODES)}"
                    )
                cur_mode = norm_mode

            entry = {
                "port": p_str,
                "state": cur_state,
                "flowcontrol": cur_fc,
                "negotiation_mode": cur_mode,
            }
            updated_item = entry
            payload_list.append(entry)
        else:
            payload_list.append(
                {
                    "port": p_str,
                    "state": cur_state,
                    "flowcontrol": cur_fc,
                    "negotiation_mode": cur_mode,
                }
            )

    res = client.write("/admin/switch?form=para", method="set", params=payload_list)
    return {
        "port": str(port_num),
        "updated": updated_item,
        "result": res,
    }


def get_interfaces_overview(client: ER605Client) -> Dict[str, Any]:
    """Retrieve WAN/LAN interface status, WAN mode, and physical switch port link states."""
    result: Dict[str, Any] = {
        "wan_mode": {},
        "normal_interfaces": [],
        "vpn_interfaces": [],
        "switch_ports": [],
    }

    try:
        wan_mode = client.read("/admin/interface_wan?form=wanmode")
        if isinstance(wan_mode, dict):
            result["wan_mode"] = wan_mode
    except ER605Error:
        pass

    status2 = client.read("/admin/interface?form=status2")
    if isinstance(status2, dict):
        normal = status2.get("normal")
        vpn = status2.get("vpn")
        if isinstance(normal, list):
            result["normal_interfaces"] = normal
        if isinstance(vpn, list):
            result["vpn_interfaces"] = vpn

    para_by_port: Dict[str, Dict[str, Any]] = {}
    try:
        for p_item in get_switch_port_params(client):
            para_by_port[str(p_item.get("port"))] = p_item
    except ER605Error:
        pass

    try:
        sw_state = client.read("/admin/switch?form=state")
        ports_list: List[Dict[str, Any]] = []
        if isinstance(sw_state, list):
            ports_list = sw_state
        elif isinstance(sw_state, dict) and sw_state:
            ports_list = [sw_state]
        for p in ports_list:
            p_key = str(p.get("port"))
            if p_key in para_by_port:
                p["admin_state"] = para_by_port[p_key].get("port_state", "on")
                p["negotiation_mode"] = para_by_port[p_key].get("negotiation_mode", "auto")
        result["switch_ports"] = ports_list
    except ER605Error:
        pass

    return result


def get_switch_port_statistics(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve physical switch port packet counters via `/admin/switch?form=statistic`."""
    stats = client.read("/admin/switch?form=statistic")
    if isinstance(stats, list):
        return stats
    if isinstance(stats, dict) and stats:
        return [stats]
    return []


def _get_active_wan_numbers(client: ER605Client) -> List[str]:
    try:
        wm = client.read("/admin/interface_wan?form=wanmode")
        if isinstance(wm, dict) and isinstance(wm.get("wan_numbers"), list):
            return [str(x) for x in wm["wan_numbers"]]
    except ER605Error:
        pass
    return ["1"]


def connect_wan_interface(client: ER605Client, wan_id: str) -> Dict[str, Any]:
    """Trigger connection on a WAN interface (`1`..`4`) or power on a LAN switch port (`1`..`5`)."""
    raw = str(wan_id).strip().upper()
    explicit_wan = raw.startswith("WAN")
    num_str = raw[3:] if explicit_wan else raw

    if not num_str.isdigit() or not (1 <= int(num_str) <= 5):
        raise ValidationError("Target must be a valid port number (1..5 or WAN1..WAN4).")

    active_wans = _get_active_wan_numbers(client)
    if num_str in active_wans:
        # Also ensure the physical switch port is powered on if it was powered off
        try:
            set_switch_port_params(client, int(num_str), state="on")
        except ER605Error:
            pass
        res = client.write(
            "/admin/interface_wan?form=connect",
            method="set",
            params={"wan_id": num_str},
        )
        return {"wan_id": num_str, "target": f"WAN{num_str}", "mode": "wan_logical", "action": "connect", "result": res}

    if explicit_wan:
        raise ValidationError(
            f"WAN{num_str} is not an active WAN interface on this router (Active WAN ports: {', '.join('WAN' + x for x in active_wans)}). "
            f"To power on physical LAN Port {num_str}, use: interface port {num_str} on"
        )

    # Target is a physical LAN switch port (e.g. Port 2..5) -> power on its PHY via /admin/switch?form=para
    phy_res = set_switch_port_params(client, int(num_str), state="on")
    return {"wan_id": num_str, "target": f"Port {num_str} (LAN)", "mode": "switch_phy", "action": "connect", "result": phy_res}


def disconnect_wan_interface(client: ER605Client, wan_id: str) -> Dict[str, Any]:
    """Trigger disconnection on a WAN interface (`1`..`4`) or physically power down a LAN switch port (`1`..`5`)."""
    raw = str(wan_id).strip().upper()
    explicit_wan = raw.startswith("WAN")
    num_str = raw[3:] if explicit_wan else raw

    if not num_str.isdigit() or not (1 <= int(num_str) <= 5):
        raise ValidationError("Target must be a valid port number (1..5 or WAN1..WAN4).")

    active_wans = _get_active_wan_numbers(client)
    if num_str in active_wans:
        res = client.write(
            "/admin/interface_wan?form=disconnect",
            method="set",
            params={"wan_id": num_str},
        )
        return {"wan_id": num_str, "target": f"WAN{num_str}", "mode": "wan_logical", "action": "disconnect", "result": res}

    if explicit_wan:
        raise ValidationError(
            f"WAN{num_str} is not an active WAN interface on this router (Active WAN ports: {', '.join('WAN' + x for x in active_wans)}). "
            f"To physically power off LAN Port {num_str}, use: interface port {num_str} off"
        )

    # Target is a physical LAN switch port (e.g. Port 2..5) -> power down its PHY via /admin/switch?form=para
    phy_res = set_switch_port_params(client, int(num_str), state="off")
    return {"wan_id": num_str, "target": f"Port {num_str} (LAN)", "mode": "switch_phy", "action": "disconnect", "result": phy_res}
