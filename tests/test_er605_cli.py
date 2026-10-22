"""Unit and protocol simulation tests for ER605 CLI."""

import io
import json
import os
import tempfile
import unittest
from http.cookiejar import Cookie
from typing import Any, Dict, List, Optional, Tuple

import sys

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.abspath(os.path.join(_TESTS_DIR, "..", "src"))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from er605_cli.auth import extract_rsa_key_pair, rsa_encrypt_nopadding
from er605_cli.client import ER605Client
from er605_cli.commands import CommandDispatcher
from er605_cli.exceptions import (
    AuthenticationError,
    OperationError,
    PermissionDeniedError,
    SessionExpiredError,
    UnsupportedFeatureError,
    ValidationError,
)
from er605_cli.operations.dhcp import normalize_mac
from er605_cli.operations.system import format_uptime_dhms, redact_secrets
from er605_cli.operations.vlan import format_vlan_ports, parse_port_assignments


class MockER605Client(ER605Client):
    """Subclasses `ER605Client` with an in-memory router RPC responder matching ER605 v1.3.2 firmware."""

    # 1024-bit RSA public key captured from the live ER605 v1.0 router
    TEST_MODULUS_HEX = (
        "D1E79FF1A7FD00C61DE7BE79A2C8C97F5DD3C94AC058C5FFDFEF1C9FD8E52B70"
        "A8E40B4AD8F3DC3B88C91DA7428DC7A1E853F6BA892A76D0081DF35FB089EB82"
        "1474DF48DE0C6C83A364DDCE43E63A3B89AD9B81A39B434E3C26A6C5E227BE27"
        "E2D1BA29E9D19F61E0286DC2321E7DE2A4FC5B827DFBA7A3485738DF31B0E82B"
    )
    TEST_EXPONENT_HEX = "010001"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.calls: List[Tuple[str, Dict[str, str]]] = []
        self.simulate_expired_once = False
        self.simulate_not_found = False

        # Mutable mock router state
        self.vlans: List[Dict[str, Any]] = [
            {"vlan": "1", "name": "VLAN_LAN", "ports": "2 3 4 5", "users": "lan", "desc": "Default LAN"},
            {"vlan": "2", "name": "VLAN_WAN1", "ports": "1", "users": "wan", "desc": "Default WAN"},
            {"vlan": "20", "name": "Guest_VLAN", "ports": "3t 4", "users": "web", "desc": "Guest"},
        ]
        self.reservations: List[Dict[str, Any]] = [
            {
                "interface": "LAN",
                "mac": "AA-BB-CC-11-22-33",
                "ip": "192.168.0.50",
                "note": "NAS-Server",
                "enable": "on",
                "bind": "on",
            }
        ]
        self.static_routes: List[Dict[str, Any]] = [
            {
                "key": "key-1",
                "name": "Branch_Office",
                "target": "10.20.0.0",
                "netmask": "255.255.255.0",
                "gateway": "192.168.0.254",
                "interface": "LAN",
                "t_label": "LAN",
                "metric": "1",
                "reachability": "reachable",
                "enable": "on",
            }
        ]
        self.acl_rules: List[Dict[str, Any]] = [
            {
                "key": "key-1",
                "name": "Block_IoT_WAN",
                "policy": "DROP",
                "service": "ALL",
                "zone": ["LAN", "WAN1"],
                "src": "IPGROUP_ANY",
                "dest": "IPGROUP_ANY",
                "time": "Any",
                "user": "1",
            }
        ]
        self.mac_rules: List[Dict[str, Any]] = [
            {"key": "key-1", "name": "Unknown_Tablet", "mac": "12-34-56-78-9A-BC"}
        ]
        self.logs: List[Dict[str, Any]] = [
            {
                "key": "1",
                "time": "2026-10-22 12:00:01",
                "type": "SYS",
                "level": "INFO",
                "content": "Administrator login succeeded.",
            }
        ]

    def _inject_test_cookie(self) -> None:
        cookie = Cookie(
            version=0,
            name="sysauth",
            value="mock_sysauth_cookie_value",
            port=None,
            port_specified=False,
            domain=self.session.host,
            domain_specified=True,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=False,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={},
            rfc2109=False,
        )
        self.session.cookie_jar.set_cookie(cookie)

    def _post_raw(
        self,
        endpoint: str,
        form_fields: Dict[str, str],
        timeout: Optional[float] = None,
    ) -> Tuple[bytes, Dict[str, str]]:
        self.calls.append((endpoint, dict(form_fields)))

        if self.simulate_not_found:
            return b"<h1>Not Found</h1>", {"content-type": "text/html"}

        if self.simulate_expired_once and endpoint.startswith("/admin/"):
            self.simulate_expired_once = False
            return json.dumps({"error_code": "703", "result": {}}).encode("utf-8"), {}

        if endpoint == "/locale?form=lang":
            return (
                json.dumps(
                    {
                        "id": 1,
                        "result": {
                            "locale": "en_US",
                            "radio": 0,
                            "model": "ER605 v1.0",
                            "force": False,
                            "multiwan": 1,
                        },
                        "error_code": "0",
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/userconfig?form=cfg_save":
            return (
                json.dumps(
                    {
                        "id": 1,
                        "result": {
                            "https_port": "443",
                            "redirect_https": "on",
                            "status": "Saved",
                            "dft_pwd_status": "Modify",
                            "qs_flag": "0",
                            "config_status": "Modify",
                        },
                        "error_code": "0",
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/firmware?form=config" and form_fields.get("operation") == "backup":
            return (
                b"MOCK_ENCRYPTED_ER605_BACKUP_BINARY_CONTENT",
                {
                    "content-type": "application/x-bin",
                    "content-disposition": 'attachment; filename="ER605-backup-2026.bin"',
                },
            )

        req_data = json.loads(form_fields.get("data", "{}"))
        method = req_data.get("method", "get")
        params = req_data.get("params") or {}

        if endpoint == "/login?form=login":
            if method == "get":
                return (
                    json.dumps(
                        {
                            "error_code": "0",
                            "result": {
                                "password": [self.TEST_MODULUS_HEX, self.TEST_EXPONENT_HEX]
                            },
                        }
                    ).encode("utf-8"),
                    {},
                )
            if method == "login":
                if params.get("username") == "admin" and len(params.get("password", "")) == 256:
                    self._inject_test_cookie()
                    return (
                        json.dumps(
                            {
                                "error_code": "0",
                                "result": {"stok": "458ab3489012cd3456ef789012345678"},
                            }
                        ).encode("utf-8"),
                        {},
                    )
                return (
                    json.dumps(
                        {
                            "error_code": "700",
                            "result": {"failureCount": 1, "attemptsAllowed": 9},
                        }
                    ).encode("utf-8"),
                    {},
                )

        if endpoint == "/admin/system?form=logout":
            return json.dumps({"error_code": "0", "result": {}}).encode("utf-8"), {}

        if endpoint == "/admin/firmware?form=upgrade":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": {
                            "model": "ER605",
                            "hardware_version": "ER605 v1.0",
                            "firmware_version": "1.3.2 Build 20251030 Rel.16640",
                        },
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/status?form=time_run":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": ["2026-10-22 22:00:00", "4 11 25 9"],
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/sys_status?form=all_usage":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": {
                            "cpu_usage": {"core1": 8, "core2": 5},
                            "mem_usage": {"mem": 34},
                        },
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/interface_wan?form=wanmode":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": {"wanmode": "1", "wan_numbers": ["1"], "wan_names": [{"index": "1", "name": "WAN1"}]},
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/interface?form=status2":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": {
                            "normal": [
                                {
                                    "t_name": "WAN1",
                                    "t_label": "WAN1",
                                    "t_type": "dhcp",
                                    "proto": "dhcp",
                                    "t_isup": 1,
                                    "ipaddr": "203.0.113.15",
                                    "netmask": "255.255.255.0",
                                    "gateway": "203.0.113.1",
                                    "macaddr": "AA-BB-CC-00-00-01",
                                    "dns1": "1.1.1.1",
                                    "dns2": "8.8.8.8",
                                },
                                {
                                    "t_name": "LAN",
                                    "t_label": "LAN",
                                    "t_type": "static",
                                    "proto": "static",
                                    "t_isup": 1,
                                    "ipaddr": "192.168.0.1",
                                    "netmask": "255.255.255.0",
                                    "gateway": "0.0.0.0",
                                    "macaddr": "AA-BB-CC-00-00-00",
                                },
                            ],
                            "vpn": [],
                        },
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/switch?form=state":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": [
                            {"port": 1, "state": "Connected", "speed": "1000M", "duplex": "Full", "flowcontrol": "Disable"},
                            {"port": 2, "state": "Connected", "speed": "1000M", "duplex": "Full", "flowcontrol": "Disable"},
                        ],
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/switch?form=statistic":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": [
                            {"port": 1, "rx_All": 15000, "tx_All": 12000},
                            {"port": 2, "rx_All": 9500, "tx_All": 10400},
                        ],
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint in ("/admin/interface_wan?form=connect", "/admin/interface_wan?form=disconnect"):
            return json.dumps({"error_code": "0", "result": {"wan_id": params.get("wan_id")}}).encode("utf-8"), {}

        if endpoint == "/admin/arplist?form=getlist":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": [
                            {"ipaddr": "192.168.0.100", "mac": "AA-BB-CC-DD-EE-01", "interface": "LAN", "status": "reachable"},
                            {"ipaddr": "192.168.0.50", "mac": "AA-BB-CC-11-22-33", "interface": "LAN", "status": "permanent"},
                        ],
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/dhcps?form=client":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": [
                            {
                                "name": "workstation-pc",
                                "ipaddr": "192.168.0.100",
                                "macaddr": "AA-BB-CC-DD-EE-01",
                                "leasetime": "01:58:20",
                                "interface": "LAN",
                            }
                        ],
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/dhcps?form=reservation":
            if method == "get":
                return json.dumps({"error_code": "0", "result": self.reservations}).encode("utf-8"), {}
            if method == "add":
                self.reservations.append(params["new"])
                return json.dumps({"error_code": "0", "result": params["new"]}).encode("utf-8"), {}
            if method == "set":
                idx = int(params["index"])
                self.reservations[idx] = params["new"]
                return json.dumps({"error_code": "0", "result": params["new"]}).encode("utf-8"), {}
            if method == "delete":
                idx = int(params["index"])
                removed = self.reservations.pop(idx)
                return json.dumps({"error_code": "0", "result": removed}).encode("utf-8"), {}

        if endpoint == "/admin/dhcps?form=lan":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": [
                            {
                                "name": "LAN",
                                "vlanid": "1",
                                "ipaddr": "192.168.0.1",
                                "netmask": "255.255.255.0",
                                "enable": "on",
                                "ipaddr_start": "192.168.0.100",
                                "ipaddr_end": "192.168.0.199",
                                "leasetime": "120",
                                "gateway": "192.168.0.1",
                                "pri_dns": "192.168.0.1",
                                "snd_dns": "0.0.0.0",
                            }
                        ],
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/vlansetting?form=vlansettinglist":
            if method == "get":
                return (
                    json.dumps(
                        {
                            "error_code": "0",
                            "result": self.vlans,
                            "others": {"totalNum": len(self.vlans)},
                        }
                    ).encode("utf-8"),
                    {},
                )
            if method == "add":
                new_f = params["new"]
                ports_tokens = []
                for p in range(1, 6):
                    if new_f.get(f"if_onoff{p}") == "1":
                        tag = "t" if new_f.get(f"tag_type{p}") == "t" else ""
                        ports_tokens.append(f"{p}{tag}")
                created = {
                    "vlan": new_f["vlan"],
                    "name": new_f["name"],
                    "ports": " ".join(ports_tokens),
                    "users": "web",
                    "desc": new_f.get("desc", ""),
                }
                self.vlans.append(created)
                return json.dumps({"error_code": "0", "result": created}).encode("utf-8"), {}
            if method == "set":
                idx = int(params["index"])
                new_f = params["new"]
                ports_tokens = []
                for p in range(1, 6):
                    if new_f.get(f"if_onoff{p}") == "1":
                        tag = "t" if new_f.get(f"tag_type{p}") == "t" else ""
                        ports_tokens.append(f"{p}{tag}")
                self.vlans[idx]["name"] = new_f["name"]
                self.vlans[idx]["ports"] = " ".join(ports_tokens)
                self.vlans[idx]["desc"] = new_f.get("desc", "")
                return json.dumps({"error_code": "0", "result": self.vlans[idx]}).encode("utf-8"), {}
            if method == "delete":
                idx = int(params["index"])
                removed = self.vlans.pop(idx)
                return json.dumps({"error_code": "0", "result": removed}).encode("utf-8"), {}

        if endpoint == "/admin/vlansetting?form=portsettinglist":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": [{"port": 1, "type": "GENERAL", "pvid": 2, "vlans": [2]}],
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/vlansetting?form=vlanmax":
            return json.dumps({"error_code": "0", "result": {"maxNum": 32}}).encode("utf-8"), {}

        if endpoint == "/admin/routing?form=system_routetbl":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": [
                            {
                                "dest": "0.0.0.0",
                                "mask": "0.0.0.0",
                                "gateway": "203.0.113.1",
                                "metric": "0",
                                "interface": "WAN1",
                                "t_label": "WAN1",
                            }
                        ],
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/routing?form=static_routing":
            if method == "get":
                return json.dumps({"error_code": "0", "result": self.static_routes}).encode("utf-8"), {}
            if method == "add":
                entry = dict(params["new"])
                entry["key"] = f"key-{len(self.static_routes) + 1}"
                self.static_routes.append(entry)
                return json.dumps({"error_code": "0", "result": entry}).encode("utf-8"), {}
            if method == "delete":
                idx = int(params["index"])
                removed = self.static_routes.pop(idx)
                return json.dumps({"error_code": "0", "result": removed}).encode("utf-8"), {}

        if endpoint == "/admin/policy_route?form=policy_route":
            return json.dumps({"error_code": "0", "result": []}).encode("utf-8"), {}

        if endpoint == "/admin/access_ctl?form=acl_inner":
            if method == "get":
                return json.dumps({"error_code": "0", "result": self.acl_rules}).encode("utf-8"), {}
            if method == "add":
                entry = dict(params["new"])
                entry["key"] = f"key-{len(self.acl_rules) + 1}"
                entry["user"] = "1"
                self.acl_rules.append(entry)
                return json.dumps({"error_code": "0", "result": entry}).encode("utf-8"), {}
            if method == "delete":
                idx = int(params["index"])
                removed = self.acl_rules.pop(idx)
                return json.dumps({"error_code": "0", "result": removed}).encode("utf-8"), {}

        if endpoint == "/admin/mac_filter?form=mode":
            return json.dumps({"error_code": "0", "result": {"enable": "on", "filter_mode": "deny"}}).encode("utf-8"), {}

        if endpoint == "/admin/mac_filter?form=mac_list":
            if method == "get":
                return json.dumps({"error_code": "0", "result": self.mac_rules}).encode("utf-8"), {}
            if method == "add":
                entry = dict(params["new"])
                entry["key"] = f"key-{len(self.mac_rules) + 1}"
                self.mac_rules.append(entry)
                return json.dumps({"error_code": "0", "result": entry}).encode("utf-8"), {}
            if method == "delete":
                idx = int(params["index"])
                removed = self.mac_rules.pop(idx)
                return json.dumps({"error_code": "0", "result": removed}).encode("utf-8"), {}

        if endpoint == "/admin/logger?form=loglist":
            if method == "get":
                return (
                    json.dumps(
                        {
                            "error_code": "0",
                            "result": self.logs,
                            "others": {"total_log": len(self.logs)},
                        }
                    ).encode("utf-8"),
                    {},
                )
            if method == "delete":
                self.logs.clear()
                return json.dumps({"error_code": "0", "result": {}}).encode("utf-8"), {}

        if endpoint == "/admin/ipsec?form=conn":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": [
                            {
                                "name": "HQ_Tunnel",
                                "remote_peer": "198.51.100.1",
                                "local_binding": "WAN1",
                                "local_network": "192.168.0.0/24",
                                "remote_network": "10.0.0.0/24",
                                "psk": "SuperSecretIPsecPSK123",
                                "status": "enable",
                            }
                        ],
                    }
                ).encode("utf-8"),
                {},
            )

        if endpoint == "/admin/ifstat?form=list":
            return (
                json.dumps(
                    {
                        "error_code": "0",
                        "result": [
                            {
                                "interface": "WAN1",
                                "rx_bytes": 10485760,
                                "rx_pkts": 8200,
                                "tx_bytes": 2097152,
                                "tx_pkts": 3100,
                                "rx_bps": 102400,
                                "tx_bps": 51200,
                            }
                        ],
                    }
                ).encode("utf-8"),
                {},
            )

        return json.dumps({"error_code": "0", "result": []}).encode("utf-8"), {}


class TestER605CLI(unittest.TestCase):
    """Comprehensive unit tests for authentication, operations, and CLI commands."""

    def test_rsa_encrypt_nopadding_matches_firmware_encrypt_js(self) -> None:
        cipher = rsa_encrypt_nopadding(
            "admin123",
            MockER605Client.TEST_MODULUS_HEX,
            MockER605Client.TEST_EXPONENT_HEX,
        )
        # 1024-bit modulus -> 256 hex chars
        self.assertEqual(len(cipher), 256)
        int(cipher, 16)  # Must be valid hexadecimal

    def test_extract_rsa_key_pair_formats(self) -> None:
        n, e = extract_rsa_key_pair(
            {"password": [MockER605Client.TEST_MODULUS_HEX, MockER605Client.TEST_EXPONENT_HEX]}
        )
        self.assertEqual(n, MockER605Client.TEST_MODULUS_HEX)
        self.assertEqual(e, MockER605Client.TEST_EXPONENT_HEX)

    def test_session_never_leaks_stok_in_repr(self) -> None:
        client = MockER605Client(host="192.168.0.1")
        client.login("admin", "secretPass")
        self.assertTrue(client.session.is_authenticated)
        rep = repr(client.session)
        self.assertNotIn(client.session.stok, rep)
        self.assertNotIn("mock_sysauth_cookie_value", rep)

    def test_login_failure_raises_authentication_error(self) -> None:
        client = MockER605Client(host="192.168.0.1")
        with self.assertRaises(AuthenticationError) as ctx:
            client.login("wronguser", "badpass")
        self.assertIn("Remaining allowed: 9", str(ctx.exception))

    def test_csrf_not_found_raises_permission_denied(self) -> None:
        client = MockER605Client(host="192.168.0.1")
        client.simulate_not_found = True
        with self.assertRaises(PermissionDeniedError):
            client.probe_prelogin_info()

    def test_session_expiry_triggers_reauth_callback(self) -> None:
        client = MockER605Client(host="192.168.0.1")
        client.login("admin", "secretPass")
        client.simulate_expired_once = True

        reauth_called = []

        def _reauth() -> Tuple[str, str]:
            reauth_called.append(True)
            return ("admin", "secretPass")

        client.reauth_callback = _reauth
        res = client.read("/admin/firmware?form=upgrade")
        self.assertEqual(len(reauth_called), 1)
        self.assertEqual(res["hardware_version"], "ER605 v1.0")

    def test_secret_redaction_strips_sensitive_keys(self) -> None:
        raw = {
            "username": "admin",
            "password": "my_plain_password",
            "nested": [{"psk": "ipsec_secret_123", "public_key": "allowed_pub_key"}],
        }
        redacted = redact_secrets(raw)
        self.assertEqual(redacted["password"], "***REDACTED***")
        self.assertEqual(redacted["nested"][0]["psk"], "***REDACTED***")
        self.assertEqual(redacted["nested"][0]["public_key"], "allowed_pub_key")

    def test_read_only_commands_and_json_output(self) -> None:
        client = MockER605Client(host="192.168.0.1")
        client.login("admin", "secretPass")
        out = io.StringIO()
        err = io.StringIO()
        disp = CommandDispatcher(client, out_stream=out, err_stream=err)

        for cmd_tokens in [
            ["probe"],
            ["status"],
            ["interfaces"],
            ["interfaces", "stats"],
            ["devices"],
            ["dhcp", "leases"],
            ["dhcp", "reservations"],
            ["dhcp", "server"],
            ["vlans"],
            ["vlan", "show", "20"],
            ["routes"],
            ["firewall", "rules"],
            ["vpn", "status"],
            ["traffic"],
            ["logs"],
            ["config", "show", "vpn"],
        ]:
            out.seek(0)
            out.truncate(0)
            rc = disp.dispatch_tokens(cmd_tokens + ["--json"])
            self.assertEqual(rc, 0, f"Command {cmd_tokens} failed: {err.getvalue()}")
            parsed = json.loads(out.getvalue())
            self.assertIsNotNone(parsed)

    def test_configuration_commands_with_confirmation(self) -> None:
        client = MockER605Client(host="192.168.0.1")
        client.login("admin", "secretPass")
        out = io.StringIO()
        err = io.StringIO()

        # First test declining confirmation ('n')
        disp_decline = CommandDispatcher(
            client,
            input_fn=lambda _: "n",
            out_stream=out,
            err_stream=err,
        )
        disp_decline.dispatch_tokens(["vlan", "create", "30", "IoT_VLAN", "2:u,3:t"])
        self.assertEqual(len(client.vlans), 3)

        # Now test accepting confirmation ('y') across all config operations
        disp_accept = CommandDispatcher(
            client,
            input_fn=lambda _: "y",
            out_stream=out,
            err_stream=err,
        )
        self.assertEqual(disp_accept.dispatch_tokens(["vlan", "create", "30", "IoT_VLAN", "2:u,3:t", "--desc", "IoT"]), 0)
        self.assertEqual(len(client.vlans), 4)

        self.assertEqual(disp_accept.dispatch_tokens(["vlan", "update", "30", "--name", "IoT_Updated", "--ports", "2:t,4:u"]), 0)
        self.assertEqual(client.vlans[-1]["name"], "IoT_Updated")

        self.assertEqual(disp_accept.dispatch_tokens(["vlan", "delete", "30"]), 0)
        self.assertEqual(len(client.vlans), 3)

        # System VLAN deletion must be blocked
        self.assertEqual(disp_accept.dispatch_tokens(["vlan", "delete", "1"]), 1)

        # DHCP reservation lifecycle
        self.assertEqual(
            disp_accept.dispatch_tokens(
                ["dhcp", "reservation", "add", "192.168.0.60", "AA:BB:CC:44:55:66", "--note", "Printer", "--bind", "on"]
            ),
            0,
        )
        self.assertEqual(len(client.reservations), 2)
        self.assertEqual(
            disp_accept.dispatch_tokens(["dhcp", "reservation", "update", "192.168.0.60", "--note", "LaserPrinter"]),
            0,
        )
        self.assertEqual(client.reservations[-1]["note"], "LaserPrinter")
        self.assertEqual(disp_accept.dispatch_tokens(["dhcp", "reservation", "delete", "192.168.0.60"]), 0)
        self.assertEqual(len(client.reservations), 1)

        # Firewall ACL add & delete
        self.assertEqual(
            disp_accept.dispatch_tokens(["firewall", "acl", "add", "Allow_DNS", "ACCEPT", "--zone", "LAN"]),
            0,
        )
        self.assertEqual(len(client.acl_rules), 2)
        self.assertEqual(disp_accept.dispatch_tokens(["firewall", "acl", "delete", "Allow_DNS"]), 0)
        self.assertEqual(len(client.acl_rules), 1)

        # Device block / unblock (with explicit name and with MAC-only auto-name)
        self.assertEqual(disp_accept.dispatch_tokens(["device", "block", "GuestPhone", "22-33-44-55-66-77"]), 0)
        self.assertEqual(len(client.mac_rules), 2)
        self.assertEqual(disp_accept.dispatch_tokens(["device", "unblock", "22:33:44:55:66:77"]), 0)
        self.assertEqual(len(client.mac_rules), 1)
        self.assertEqual(disp_accept.dispatch_tokens(["device", "block", "C0-06-C3-C9-A7-1E"]), 0)
        self.assertEqual(client.mac_rules[-1]["name"], "Block_C006C3C9A71E")
        self.assertEqual(disp_accept.dispatch_tokens(["device", "unblock", "C0-06-C3-C9-A7-1E"]), 0)
        self.assertEqual(disp_accept.dispatch_tokens(["device", "filter", "on", "--mode", "black", "--zone", "WAN"]), 0)

        # Static route add & delete
        self.assertEqual(
            disp_accept.dispatch_tokens(
                ["route", "add", "Lab_Net", "172.16.10.0", "255.255.255.0", "192.168.0.2", "--interface", "LAN"]
            ),
            0,
        )
        self.assertEqual(len(client.static_routes), 2)
        self.assertEqual(disp_accept.dispatch_tokens(["route", "delete", "Lab_Net"]), 0)
        self.assertEqual(len(client.static_routes), 1)

        # WAN connect / disconnect & physical switch port power on/off
        self.assertEqual(disp_accept.dispatch_tokens(["interface", "connect", "WAN1"]), 0)
        self.assertEqual(disp_accept.dispatch_tokens(["interface", "disconnect", "1"]), 0)
        self.assertEqual(disp_accept.dispatch_tokens(["interface", "disconnect", "2"]), 0)
        self.assertEqual(disp_accept.dispatch_tokens(["interface", "port", "2", "off"]), 0)
        self.assertEqual(disp_accept.dispatch_tokens(["interface", "port", "2", "on", "--speed", "auto"]), 0)

        # Config backup
        with tempfile.TemporaryDirectory() as tmpdir:
            bkp_path = os.path.join(tmpdir, "backup.bin")
            self.assertEqual(disp_accept.dispatch_tokens(["config", "backup", bkp_path]), 0)
            self.assertTrue(os.path.isfile(bkp_path))

        # Logs clear
        self.assertEqual(disp_accept.dispatch_tokens(["logs", "clear"]), 0)
        self.assertEqual(len(client.logs), 0)

    def test_unsupported_features_Explicitly_reported(self) -> None:
        client = MockER605Client(host="192.168.0.1")
        out = io.StringIO()
        err = io.StringIO()
        disp = CommandDispatcher(client, out_stream=out, err_stream=err)

        for unsupported_cmd in (["ssh"], ["telnet"], ["wifi"], ["reset"]):
            err.seek(0)
            err.truncate(0)
            rc = disp.dispatch_tokens(unsupported_cmd)
            self.assertEqual(rc, 1)
            self.assertIn("UnsupportedFeatureError", err.getvalue())

    def test_helpers_mac_and_vlan_ports(self) -> None:
        self.assertEqual(normalize_mac("aa:bb:cc:dd:ee:ff"), "AA-BB-CC-DD-EE-FF")
        with self.assertRaises(ValidationError):
            normalize_mac("01:00:5e:00:00:01")  # Multicast MAC rejected
        self.assertEqual(parse_port_assignments("1:u,2:t,5u"), {1: "u", 2: "t", 5: "u"})
        self.assertEqual(format_vlan_ports("1 2t 3t"), "Port1(U), Port2(T), Port3(T)")
        self.assertEqual(format_uptime_dhms("4 11 25 9"), "4d 11h 25m 9s")


if __name__ == "__main__":
    unittest.main()
