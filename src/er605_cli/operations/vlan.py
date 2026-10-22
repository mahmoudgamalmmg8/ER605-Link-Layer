"""VLAN and switch port configuration operations for ER605.

Endpoints verified against firmware (`vlan_setting.lua`, `vlan_vlanSetting.html`):
- `/admin/vlansetting?form=vlansettinglist` (`method=get|add|set|delete`)
- `/admin/vlansetting?form=portsettinglist` (`method=get|set`)
- `/admin/vlansetting?form=linktype` (`method=get`)
- `/admin/vlansetting?form=vlanmax` (`method=get`)
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from ..client import ER605Client
from ..exceptions import ER605Error, ValidationError


def format_vlan_ports(ports_str: str) -> str:
    """Format ER605 VLAN `ports` string (e.g. `'1 2t 3t'`) into readable form (`'1(U) 2(T) 3(T)'`)."""
    raw = str(ports_str or "").strip()
    if not raw:
        return "---"
    tokens = raw.split()
    out: List[str] = []
    for tok in tokens:
        m = re.match(r"^(\d+)(t?)$", tok.strip())
        if m:
            pnum = m.group(1)
            tag = "T" if m.group(2) == "t" else "U"
            out.append(f"Port{pnum}({tag})")
        else:
            out.append(tok)
    return ", ".join(out)


def parse_port_assignments(ports_spec: str) -> Dict[int, str]:
    """Parse user port spec like `'1:u,2:t,3:u'` or `'1u,2t'` into `{port_num: 'u'|'t'}`.

    ER605 switch ports are numbered 1..5 (corresponding to physical RJ45 ports 1..5).
    """
    if not ports_spec or not str(ports_spec).strip():
        raise ValidationError(
            "Port specification is required (e.g. '2:u,3:t' or '2u,3t' for untagged/tagged ports)."
        )
    assignments: Dict[int, str] = {}
    for item in re.split(r"[,\s]+", str(ports_spec).strip()):
        if not item:
            continue
        m = re.match(r"^(\d+)(?:[:]?([utUT]))?$", item.strip())
        if not m:
            raise ValidationError(
                f"Invalid port assignment '{item}'. Use '<port>:u' (untagged) or '<port>:t' (tagged), e.g. '3:t,4:u'."
            )
        pnum = int(m.group(1))
        if pnum < 1 or pnum > 5:
            raise ValidationError(f"Invalid physical port number {pnum}; ER605 ports are 1..5.")
        tag = (m.group(2) or "u").lower()
        assignments[pnum] = tag
    if not assignments:
        raise ValidationError("At least one physical port (1..5) must be assigned to the VLAN.")
    return assignments


def get_vlans(client: ER605Client) -> Dict[str, Any]:
    """Retrieve VLAN groups, port settings, link types, and VLAN limits."""
    resp = client.request_Full("/admin/vlansetting?form=vlansettinglist", method="get")
    vlans = resp.get("result")
    if not isinstance(vlans, list):
        vlans = [vlans] if isinstance(vlans, dict) and vlans else []
    others = resp.get("others") or {}

    ports: List[Dict[str, Any]] = []
    try:
        p_res = client.read("/admin/vlansetting?form=portsettinglist")
        if isinstance(p_res, list):
            ports = p_res
    except ER605Error:
        pass

    vlan_max: Dict[str, Any] = {}
    try:
        m_res = client.read("/admin/vlansetting?form=vlanmax")
        if isinstance(m_res, dict):
            vlan_max = m_res
    except ER605Error:
        pass

    return {
        "vlans": vlans,
        "ports": ports,
        "total_num": others.get("totalNum", len(vlans)),
        "limits": vlan_max,
    }


def get_vlan_by_id(client: ER605Client, vlan_id: str) -> Dict[str, Any]:
    """Retrieve a specific VLAN by its VLAN ID."""
    vid_str = str(vlan_id).strip()
    data = get_vlans(client)
    for v in data["vlans"]:
        if str(v.get("vlan")) == vid_str:
            return v
    raise ValidationError(f"VLAN {vid_str} does not exist.")


def _build_vlan_editor_fields(
    vlan_id: int,
    name: str,
    port_map: Dict[int, str],
    desc: str = "",
) -> Dict[str, Any]:
    """Construct the exact form field dict expected by `vlan_setting.lua` (`add_vlan_setting_group`/`modify_vlan_setting_group`)."""
    fields: Dict[str, Any] = {
        "vlan": str(vlan_id),
        "name": name,
        "desc": desc,
    }
    for p in range(1, 6):
        if p in port_map:
            fields[f"if_onoff{p}"] = "1"
            fields[f"tag_type{p}"] = port_map[p]
        else:
            fields[f"if_onoff{p}"] = "0"
            fields[f"tag_type{p}"] = "u"
    return fields


def create_vlan(
    client: ER605Client,
    vlan_id: int,
    name: str,
    ports_spec: str,
    desc: str = "",
) -> Any:
    """Create a new 802.1Q VLAN via `/admin/vlansetting?form=vlansettinglist` (`method=add`)."""
    try:
        vid = int(vlan_id)
    except (ValueError, TypeError) as exc:
        raise ValidationError("VLAN ID must be an integer between 1 and 4094.") from exc
    if not (1 <= vid <= 4094):
        raise ValidationError("VLAN ID must be between 1 and 4094.")

    clean_name = str(name or "").strip()
    if not clean_name or len(clean_name) > 50:
        raise ValidationError("VLAN name must be between 1 and 50 characters.")

    port_map = parse_port_assignments(ports_spec)
    current = get_vlans(client)["vlans"]
    for item in current:
        if str(item.get("vlan")) == str(vid):
            raise ValidationError(f"VLAN {vid} already exists.")
        if item.get("name") == clean_name:
            raise ValidationError(f"A VLAN with name '{clean_name}' already exists.")

    new_obj = _build_vlan_editor_fields(vid, clean_name, port_map, desc=desc)
    return client.write(
        "/admin/vlansetting?form=vlansettinglist",
        method="add",
        params={
            "index": len(current),
            "old": "add",
            "new": new_obj,
            "vlan": "add",
        },
        timeout=30.0,
    )


def update_vlan(
    client: ER605Client,
    vlan_id: int,
    name: Optional[str] = None,
    ports_spec: Optional[str] = None,
    desc: Optional[str] = None,
) -> Any:
    """Modify an existing web-created VLAN via `/admin/vlansetting?form=vlansettinglist` (`method=set`)."""
    vid = int(vlan_id)
    current = get_vlans(client)["vlans"]
    idx = None
    existing = None
    for i, item in enumerate(current):
        if str(item.get("vlan")) == str(vid):
            idx = i
            existing = item
            break

    if idx is None or existing is None:
        raise ValidationError(f"VLAN {vid} not found.")

    if existing.get("users") in ("system", "wan", "lan", "iptv", "ipphone"):
        raise ValidationError(
            f"VLAN {vid} is a system/interface VLAN (used by '{existing.get('users')}') and cannot be modified directly via the 802.1Q VLAN table."
        )

    # Parse existing ports if ports_spec is not provided
    old_port_map: Dict[int, str] = {}
    for tok in str(existing.get("ports", "")).split():
        m = re.match(r"^(\d+)(t?)$", tok.strip())
        if m:
            old_port_map[int(m.group(1))] = "t" if m.group(2) == "t" else "u"

    new_port_map = parse_port_assignments(ports_spec) if ports_spec is not None else old_port_map
    new_name = str(name).strip() if name is not None else str(existing.get("name", f"VLAN{vid}"))
    new_desc = str(desc) if desc is not None else str(existing.get("desc", ""))

    old_obj = _build_vlan_editor_fields(
        vid,
        str(existing.get("name", "")),
        old_port_map,
        desc=str(existing.get("desc", "")),
    )
    new_obj = _build_vlan_editor_fields(vid, new_name, new_port_map, desc=new_desc)

    return client.write(
        "/admin/vlansetting?form=vlansettinglist",
        method="set",
        params={
            "index": idx,
            "old": old_obj,
            "new": new_obj,
            "vlan": str(vid),
        },
        timeout=30.0,
    )


def delete_vlan(client: ER605Client, vlan_id: int) -> Any:
    """Delete a VLAN by VLAN ID via `/admin/vlansetting?form=vlansettinglist` (`method=delete`)."""
    vid = int(vlan_id)
    current = get_vlans(client)["vlans"]
    idx = None
    existing = None
    for i, item in enumerate(current):
        if str(item.get("vlan")) == str(vid):
            idx = i
            existing = item
            break

    if idx is None or existing is None:
        raise ValidationError(f"VLAN {vid} not found.")

    users = existing.get("users")
    if users and users != "web":
        raise ValidationError(
            f"VLAN {vid} is in use by '{users}' and cannot be deleted."
        )

    return client.write(
        "/admin/vlansetting?form=vlansettinglist",
        method="delete",
        params={
            "key": str(vid),
            "index": str(idx),
        },
        timeout=30.0,
    )
