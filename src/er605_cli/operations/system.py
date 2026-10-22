"""System status, health, logs, and configuration operations for ER605.

Endpoints verified against firmware:
- `/locale?form=lang` (`operation=read`)
- `/userconfig?form=cfg_save` (`method=get`)
- `/admin/firmware?form=upgrade` (`method=get`) -> model, hardware_version, firmware_version
- `/admin/status?form=version` (`method=get`) -> [hw_version, sw_version]
- `/admin/status?form=time_run` (`method=get`) -> [sys_time, uptime_str]
- `/admin/time?form=settings` (`method=get`) -> timezone, time, date
- `/admin/sys_status?form=all_usage` (`method=get`) -> cpu_usage, mem_usage, cpu_log
- `/admin/sys_status?form=cpu_usage` (`method=get`) -> core1..core4
- `/admin/sys_status?form=mem_usage` (`method=get`) -> mem
- `/admin/logger?form=loglist` (`method=get`, `params={"page_num":1,"page_size":50}`)
- `/admin/logger?form=setting` (`method=get|set`)
- `/admin/remote_mngt?form=remote_mngt` (`method=get`)
- `/admin/snmp?form=snmp` (`method=get`)
- `/admin/upnp?form=upnp_global` (`method=get`)
- `/admin/firmware?form=config` (`operation=backup`, `method=reboot`)
"""

import os
from typing import Any, Dict, List, Optional

from ..client import ER605Client
from ..exceptions import ER605Error, ValidationError

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "psk",
    "presharekey",
    "preshared_key",
    "private_key",
    "secret",
    "authPass",
    "privPass",
    "stok",
    "sysauth",
    "ca_pwd",
}


def redact_secrets(obj: Any) -> Any:
    """Recursively redact sensitive keys from configuration dicts/lists."""
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if str(k) in SENSITIVE_KEYS or any(
                s in str(k).lower() for s in ("password", "passwd", "secret", "private_key", "psk")
            ):
                out[k] = "***REDACTED***" if v not in (None, "", []) else v
            else:
                out[k] = redact_secrets(v)
        return out
    if isinstance(obj, list):
        return [redact_secrets(item) for item in obj]
    return obj


def format_uptime_dhms(raw_uptime: str) -> str:
    """Convert ER605 `time_run` uptime string ('D H M S') into 'Xd Xh Xm Xs'."""
    parts = str(raw_uptime or "").strip().split()
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}d {parts[1]}h {parts[2]}m {parts[3]}s"
    return str(raw_uptime or "")


def get_system_status(client: ER605Client) -> Dict[str, Any]:
    """Retrieve comprehensive router health, firmware version, time, uptime, and CPU/memory load."""
    status_data: Dict[str, Any] = {
        "host": client.session.host,
        "model": client.session.model,
        "hardware_version": None,
        "firmware_version": None,
        "system_time": None,
        "uptime": None,
        "uptime_raw": None,
        "cpu_usage": {},
        "mem_usage": None,
        "config_status": None,
        "https_port": None,
        "redirect_https": None,
    }

    # Pre-login / general config save state
    try:
        pre = client.probe_prelogin_info()
        status_data["model"] = pre.get("locale", {}).get("model", status_data["model"])
        cfg = pre.get("config_state", {})
        status_data["config_status"] = cfg.get("status")
        status_data["https_port"] = cfg.get("https_port")
        status_data["redirect_https"] = cfg.get("redirect_https")
    except ER605Error:
        pass

    # Firmware upgrade info endpoint (used by system_state.html)
    try:
        fw_info = client.read("/admin/firmware?form=upgrade")
        if isinstance(fw_info, dict):
            status_data["model"] = fw_info.get("model") or status_data["model"]
            status_data["hardware_version"] = fw_info.get("hardware_version")
            status_data["firmware_version"] = fw_info.get("firmware_version")
    except ER605Error:
        pass

    # Fallback/complement with /admin/status?form=version
    if not status_data["hardware_version"] or not status_data["firmware_version"]:
        try:
            ver_list = client.read("/admin/status?form=version")
            if isinstance(ver_list, list) and len(ver_list) >= 2:
                status_data["hardware_version"] = status_data["hardware_version"] or ver_list[0]
                status_data["firmware_version"] = status_data["firmware_version"] or ver_list[1]
        except ER605Error:
            pass

    # Time and uptime from /admin/status?form=time_run
    try:
        time_run = client.read("/admin/status?form=time_run")
        if isinstance(time_run, list) and len(time_run) >= 2:
            status_data["system_time"] = str(time_run[0]).strip()
            status_data["uptime_raw"] = str(time_run[1]).strip()
            status_data["uptime"] = format_uptime_dhms(status_data["uptime_raw"])
    except ER605Error:
        pass

    # CPU and Memory usage from /admin/sys_status?form=all_usage
    try:
        usage = client.read("/admin/sys_status?form=all_usage")
        if isinstance(usage, dict):
            cpu_u = usage.get("cpu_usage")
            if isinstance(cpu_u, dict):
                status_data["cpu_usage"] = cpu_u
            mem_u = usage.get("mem_usage")
            if isinstance(mem_u, dict):
                status_data["mem_usage"] = mem_u.get("mem")
            elif mem_u is not None:
                status_data["mem_usage"] = mem_u
    except ER605Error:
        pass

    return status_data


def get_system_logs(
    client: ER605Client,
    page_num: int = 1,
    page_size: int = 50,
) -> Dict[str, Any]:
    """Retrieve system logs from `/admin/logger?form=loglist` and log filter settings."""
    if page_num < 1:
        raise ValidationError("page_num must be >= 1.")
    if page_size < 1 or page_size > 500:
        raise ValidationError("page_size must be between 1 and 500.")

    resp = client.request_Full(
        "/admin/logger?form=loglist",
        method="get",
        params={"page_num": page_num, "page_size": page_size},
    )
    entries = resp.get("result")
    if not isinstance(entries, list):
        entries = [entries] if isinstance(entries, dict) and entries else []
    others = resp.get("others") or {}

    settings = {}
    try:
        s_res = client.read("/admin/logger?form=setting")
        if isinstance(s_res, dict):
            settings = s_res
    except ER605Error:
        pass

    return {
        "logs": entries,
        "total_log": others.get("total_log", len(entries)),
        "page_num": page_num,
        "page_size": page_size,
        "settings": settings,
    }


def clear_system_logs(client: ER605Client) -> Dict[str, Any]:
    """Delete all system logs via `/admin/logger?form=loglist` (`method=delete`)."""
    client.write("/admin/logger?form=loglist", method="delete", params={})
    return {"cleared": True}


def get_config_summary(client: ER605Client, section: str = "all") -> Dict[str, Any]:
    """Retrieve selected router configuration settings with all secrets redacted."""
    valid_sections = {"all", "system", "network", "dhcp", "vlan", "firewall", "vpn", "services"}
    section = section.lower().strip()
    if section not in valid_sections:
        raise ValidationError(
            f"Unknown config section '{section}'. Valid sections: {', '.join(sorted(valid_sections))}"
        )

    summary: Dict[str, Any] = {}

    if section in ("all", "system"):
        sys_cfg: Dict[str, Any] = {}
        for key, ep in [
            ("config_save", "/userconfig?form=cfg_save"),
            ("firmware", "/admin/firmware?form=upgrade"),
            ("time", "/admin/time?form=settings"),
            ("remote_management", "/admin/remote_mngt?form=remote_mngt"),
            ("controller_settings", "/admin/controllerSettings?form=controllerStatus"),
        ]:
            try:
                sys_cfg[key] = redact_secrets(client.read(ep))
            except ER605Error as exc:
                sys_cfg[key] = {"error": str(exc)}
        summary["system"] = sys_cfg

    if section in ("all", "network"):
        net_cfg: Dict[str, Any] = {}
        for key, ep in [
            ("wan_mode", "/admin/interface_wan?form=wanmode"),
            ("interfaces", "/admin/interface?form=status2"),
            ("lan_networks", "/admin/dhcps?form=lan"),
            ("static_routes", "/admin/routing?form=static_routing"),
        ]:
            try:
                net_cfg[key] = redact_secrets(client.read(ep))
            except ER605Error as exc:
                net_cfg[key] = {"error": str(exc)}
        summary["network"] = net_cfg

    if section in ("all", "dhcp"):
        dhcp_cfg: Dict[str, Any] = {}
        for key, ep in [
            ("lan_dhcp", "/admin/dhcps?form=lan"),
            ("reservations", "/admin/dhcps?form=reservation"),
        ]:
            try:
                dhcp_cfg[key] = redact_secrets(client.read(ep))
            except ER605Error as exc:
                dhcp_cfg[key] = {"error": str(exc)}
        summary["dhcp"] = dhcp_cfg

    if section in ("all", "vlan"):
        vlan_cfg: Dict[str, Any] = {}
        for key, ep in [
            ("vlans", "/admin/vlansetting?form=vlansettinglist"),
            ("ports", "/admin/vlansetting?form=portsettinglist"),
            ("switch_params", "/admin/switch?form=para"),
        ]:
            try:
                vlan_cfg[key] = redact_secrets(client.read(ep))
            except ER605Error as exc:
                vlan_cfg[key] = {"error": str(exc)}
        summary["vlan"] = vlan_cfg

    if section in ("all", "firewall"):
        fw_cfg: Dict[str, Any] = {}
        for key, ep in [
            ("acl_rules", "/admin/access_ctl?form=acl_inner"),
            ("dos_defense", "/admin/dos_defense?form=settings"),
            ("flood_defense", "/admin/flood_defense?form=settings"),
            ("mac_filter_mode", "/admin/mac_filter?form=mode"),
            ("mac_filter_list", "/admin/mac_filter?form=mac_list"),
            ("ip_mac_binding_global", "/admin/imb?form=enable"),
            ("ip_mac_binding_list", "/admin/imb?form=bind_list"),
        ]:
            try:
                fw_cfg[key] = redact_secrets(client.read(ep))
            except ER605Error as exc:
                fw_cfg[key] = {"error": str(exc)}
        summary["firewall"] = fw_cfg

    if section in ("all", "vpn"):
        vpn_cfg: Dict[str, Any] = {}
        for key, ep in [
            ("ipsec_connections", "/admin/ipsec?form=conn"),
            ("openvpn_servers", "/admin/openvpn?form=server_standalone"),
            ("openvpn_clients", "/admin/openvpn?form=client_standalone"),
            ("wireguard", "/admin/wireguard?form=wireguard"),
            ("l2tp_servers", "/admin/l2tp?form=server"),
            ("l2tp_clients", "/admin/l2tp?form=client"),
            ("pptp_servers", "/admin/pptp_server?form=server_enable"),
            ("pptp_clients", "/admin/pptp_client?form=client_list"),
        ]:
            try:
                vpn_cfg[key] = redact_secrets(client.read(ep))
            except ER605Error as exc:
                vpn_cfg[key] = {"error": str(exc)}
        summary["vpn"] = vpn_cfg

    if section in ("all", "services"):
        svc_cfg: Dict[str, Any] = {}
        for key, ep in [
            ("snmp", "/admin/snmp?form=snmp"),
            ("upnp_global", "/admin/upnp?form=upnp_global"),
            ("upnp_rules", "/admin/upnp?form=server_rule"),
            ("nat_alg", "/admin/nat?form=alg"),
            ("virtual_servers", "/admin/nat?form=vs"),
        ]:
            try:
                svc_cfg[key] = redact_secrets(client.read(ep))
            except ER605Error as exc:
                svc_cfg[key] = {"error": str(exc)}
        summary["services"] = svc_cfg

    return summary


def save_config_backup(client: ER605Client, output_path: str) -> Dict[str, Any]:
    """Download encrypted router configuration backup via `/admin/firmware?form=config` (`operation=backup`)."""
    if not output_path:
        raise ValidationError("Output file path is required for configuration backup.")

    raw_bytes, server_filename = client.download_binary(
        "/admin/firmware?form=config",
        form_fields={"operation": "backup"},
    )
    resolved = os.path.abspath(os.path.expanduser(output_path))
    if os.path.isdir(resolved):
        fname = server_filename or "er605-backup.bin"
        resolved = os.path.join(resolved, fname)

    parent = os.path.dirname(resolved)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(resolved, "wb") as f:
        f.write(raw_bytes)

    return {
        "saved": True,
        "path": resolved,
        "bytes": len(raw_bytes),
        "server_filename": server_filename,
    }
