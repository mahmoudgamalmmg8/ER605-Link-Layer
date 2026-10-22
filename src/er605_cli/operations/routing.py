"""Static routing, system routing table, and policy routing operations for ER605.

Endpoints verified against firmware (`routing.lua`, `policy_route.lua`, `static_routing.html`, `system_routetbl.html`):
- `/admin/routing?form=system_routetbl` (`method=get`) -> active system routes (`dest`, `mask`, `gateway`, `metric`, `interface`)
- `/admin/routing?form=static_routing` (`method=get|add|set|delete`) -> configured static routes
- `/admin/policy_route?form=policy_route` (`method=get`) -> configured policy routes
"""

import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from ..client import ER605Client
from ..exceptions import ER605Error, ValidationError


def normalize_network_and_mask(target: str, netmask: str) -> Tuple[str, str]:
    """Validate destination IPv4 address and subnet mask, masking target to network address (matching `static_routing.html` validator)."""
    try:
        net = ipaddress.IPv4Network(f"{target.strip()}/{netmask.strip()}", strict=False)
    except ValueError as exc:
        raise ValidationError(f"Invalid target network/netmask '{target}' / '{netmask}': {exc}") from exc
    return str(net.network_address), str(net.netmask)


def get_system_routes(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve active kernel/system routing table via `/admin/routing?form=system_routetbl`."""
    res = client.read("/admin/routing?form=system_routetbl")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and res:
        return [res]
    return []


def get_static_routes(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve configured static routes via `/admin/routing?form=static_routing`."""
    res = client.read("/admin/routing?form=static_routing")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and res:
        return [res]
    return []


def get_policy_routes(client: ER605Client) -> List[Dict[str, Any]]:
    """Retrieve configured policy routing rules via `/admin/policy_route?form=policy_route`."""
    res = client.read("/admin/policy_route?form=policy_route")
    if isinstance(res, list):
        return res
    if isinstance(res, dict) and res:
        return [res]
    return []


def get_all_routes(client: ER605Client) -> Dict[str, Any]:
    """Retrieve system routing table, static routes, and policy routes."""
    sys_routes = get_system_routes(client)
    static_routes: List[Dict[str, Any]] = []
    policy_routes: List[Dict[str, Any]] = []
    try:
        static_routes = get_static_routes(client)
    except ER605Error:
        pass
    try:
        policy_routes = get_policy_routes(client)
    except ER605Error:
        pass

    return {
        "system_routes": sys_routes,
        "static_routes": static_routes,
        "policy_routes": policy_routes,
    }


def add_static_route(
    client: ER605Client,
    name: str,
    target: str,
    netmask: str,
    gateway: str,
    interface: str = "WAN1",
    metric: int = 0,
    note: str = "",
    enable: str = "on",
) -> Any:
    """Add a static route via `/admin/routing?form=static_routing` (`method=add`)."""
    clean_name = str(name or "").strip()
    if not clean_name or len(clean_name) > 32:
        raise ValidationError("Route name must be 1..32 characters.")

    net_addr, mask_addr = normalize_network_and_mask(target, netmask)
    try:
        gw_addr = str(ipaddress.IPv4Address(gateway.strip()))
    except ValueError as exc:
        raise ValidationError(f"Invalid gateway IPv4 address '{gateway}'.") from exc

    try:
        metric_int = int(metric)
    except (ValueError, TypeError) as exc:
        raise ValidationError("Metric must be an integer between 0 and 15.") from exc
    if not (0 <= metric_int <= 15):
        raise ValidationError("Metric must be between 0 and 15.")

    en_val = "on" if str(enable).lower() in ("on", "true", "1", "yes", "enable") else "off"

    existing = get_static_routes(client)
    for r in existing:
        if r.get("name") == clean_name:
            raise ValidationError(f"Static route named '{clean_name}' already exists.")

    new_obj = {
        "name": clean_name,
        "target": net_addr,
        "netmask": mask_addr,
        "gateway": gw_addr,
        "interface": interface,
        "metric": str(metric_int),
        "note": note,
        "enable": en_val,
    }
    return client.write(
        "/admin/routing?form=static_routing",
        method="add",
        params={
            "index": len(existing),
            "old": "add",
            "new": new_obj,
            "key": "add",
        },
    )


def delete_static_route(client: ER605Client, name_or_key: str) -> Any:
    """Delete a static route by rule name or key via `/admin/routing?form=static_routing` (`method=delete`)."""
    ident = str(name_or_key or "").strip()
    existing = get_static_routes(client)
    idx = None
    matched = None
    for i, r in enumerate(existing):
        if r.get("name") == ident or str(r.get("key")) == ident:
            idx = i
            matched = r
            break

    if idx is None or matched is None:
        raise ValidationError(f"Static route '{ident}' not found.")

    key_val = str(matched.get("key") or f"key-{idx}")
    return client.write(
        "/admin/routing?form=static_routing",
        method="delete",
        params={
            "key": key_val,
            "index": str(idx),
        },
    )
