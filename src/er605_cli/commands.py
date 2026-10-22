"""Interactive command shell and command dispatcher for ER605 CLI."""

import cmd
import getpass
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from .client import ER605Client
from .exceptions import (
    AuthenticationError,
    ER605Error,
    PermissionDeniedError,
    SessionExpiredError,
    UnsupportedFeatureError,
    ValidationError,
)
from .operations.dhcp import (
    add_dhcp_reservation,
    delete_dhcp_reservation,
    get_connected_devices,
    get_dhcp_leases,
    get_dhcp_reservations,
    get_lan_dhcp_settings,
    update_dhcp_reservation,
)
from .operations.firewall import (
    add_acl_rule,
    add_mac_filter_rule,
    delete_acl_rule,
    delete_mac_filter_rule,
    get_firewall_overview,
    get_mac_filtering,
    set_mac_filtering_mode,
)
from .operations.interfaces import (
    connect_wan_interface,
    disconnect_wan_interface,
    get_interfaces_overview,
    get_switch_port_statistics,
    set_switch_port_params,
)
from .operations.routing import (
    add_static_route,
    delete_static_route,
    get_all_routes,
)
from .operations.system import (
    clear_system_logs,
    get_config_summary,
    get_system_logs,
    get_system_status,
    save_config_backup,
)
from .operations.traffic import get_traffic_overview
from .operations.vlan import (
    create_vlan,
    delete_vlan,
    format_vlan_ports,
    get_vlan_by_id,
    get_vlans,
    update_vlan,
)
from .operations.vpn import get_vpn_status
from .output import (
    format_json,
    render_devices,
    render_dhcp_leases,
    render_dhcp_reservations,
    render_dhcp_server,
    render_firewall,
    render_interfaces,
    render_logs,
    render_routes,
    render_status,
    render_table,
    render_traffic,
    render_vlans,
    render_vpn_status,
)
from .parser import parse_flag_options, tokenize_command_line

HELP_TEXT = """
ER605 CLI — Supported Commands
==============================

A. Session & Authentication
  probe                                     Check pre-login connectivity, model, and config state (no auth required)
  connect <host> [--scheme http|https] [--port N] [--insecure]
                                            Change target router address and reset current session
  login [username]                          Authenticate to the router via RSA-encrypted LuCI RPC
  logout                                    Log out and invalidate the current session token
  exit | quit                               Close the session cleanly and exit

B. Read-Only Inspection
  status                                    Router health, model, firmware version, uptime, CPU & memory load
  interfaces [stats]                        WAN/LAN interfaces, WAN mode, and switch port link states (or packet stats)
  devices                                   Connected devices correlated from ARP table and active DHCP leases
  dhcp leases                               Active DHCP client leases
  dhcp reservations                         Configured static DHCP reservations
  dhcp server                               LAN networks and DHCP server pool settings
  vlans | vlan list                         Configured 802.1Q VLANs and switch port VLAN/PVID settings
  vlan show <vlan_id>                       Detailed view of a single 802.1Q VLAN
  routes                                    Active system routing table, static routes, and policy routes
  firewall rules                            ACL rules, DoS/flood defense, MAC filtering, IP-MAC binding, and NAT
  vpn status                                IPsec policies/SAs, OpenVPN, WireGuard, L2TP, and PPTP tunnel status
  traffic                                   Interface RX/TX counters & rates, per-IP traffic, and switch stats
  logs [page] [page_size]                   System log entries (default: page 1, 50 entries)
  config show [section]                     Redacted config summary (all|system|network|dhcp|vlan|firewall|vpn|services)

C. Configuration & Control (Requires confirmation [y/N] or --yes)
  vlan create <id> <name> <ports> [--desc <text>]
                                            Create 802.1Q VLAN (e.g., vlan create 20 Guest "2:u,3:t" --desc "Guest LAN")
  vlan update <id> [--name <n>] [--ports <p>] [--desc <text>]
                                            Modify a user-created 802.1Q VLAN
  vlan delete <id>                          Delete a user-created 802.1Q VLAN
  dhcp reservation add <ip> <mac> [--interface LAN] [--note <text>] [--bind on|off] [--enable on|off]
                                            Add a static DHCP reservation
  dhcp reservation update <ip> [--new-ip <ip>] [--mac <mac>] [--interface <if>] [--note <t>] [--bind on|off] [--enable on|off]
                                            Modify an existing static DHCP reservation
  dhcp reservation delete <ip>              Delete a static DHCP reservation
  firewall acl add <name> <ACCEPT|DROP> [--zone LAN] [--service ALL] [--src IPGROUP_ANY] [--dest IPGROUP_ANY] [--time Any]
                                            Add an Access Control (ACL) firewall rule
  firewall acl delete <name_or_key>         Delete a user-created ACL firewall rule
  device block [<name>] <mac>               Add device MAC address to the router's MAC filter list
  device unblock <name_or_mac>              Remove device from the router's MAC filter list
  device filter <on|off> [--mode black|white] [--zone WAN|ALL]
                                            Enable/disable global MAC filtering enforcement
  route add <name> <target> <mask> <gw> [--interface WAN1] [--metric 0] [--note <text>]
                                            Add a static IPv4 route
  route delete <name_or_key>                Delete a static IPv4 route
  interface connect <port_or_wan>           Connect WAN1..4 or power on physical switch port 1..5
  interface disconnect <port_or_wan>        Disconnect WAN1..4 or power down physical switch port 1..5
  interface port <1..5> <on|off> [--flowcontrol on|off] [--speed auto|1000MF|100MF|100MH|10MF|10MH]
                                            Physically power on/off or configure RJ45 switch port 1..5
  config backup <output_path>               Download encrypted router configuration backup (.bin)
  logs clear                                Clear all router system log entries

Global Flags (usable on any command)
  --json, -j                                Output raw structured JSON instead of formatted tables
  --yes, -y                                 Confirm configuration operation without interactive prompt

Explicitly Unsupported / Disabled Features on ER605 v1.3.2 Firmware
  ssh / telnet                              Disabled by default in firmware; root SSH password is dynamically salted
  wifi / wireless                           ER605 v1.0 is a wired-only multi-WAN gateway (`radio: 0`)
  reset / factory-reset                     Blocked by CLI safety policy to prevent accidental router wipe
""".strip()


class CommandDispatcher:
    """Executes parsed CLI commands against an `ER605Client` instance."""

    def __init__(
        self,
        client: ER605Client,
        default_json: bool = False,
        auto_confirm: bool = False,
        input_fn: Callable[[str], str] = input,
        password_fn: Callable[[str], str] = getpass.getpass,
        out_stream: Any = None,
        err_stream: Any = None,
    ) -> None:
        self.client = client
        self.default_json = default_json
        self.auto_confirm = auto_confirm
        self.input_fn = input_fn
        self.password_fn = password_fn
        self.out = out_stream or sys.stdout
        self.err = err_stream or sys.stderr

        if self.client.reauth_callback is None:
            self.client.reauth_callback = self._interactive_reauth

    def _print(self, text: str) -> None:
        print(text, file=self.out)

    def _print_err(self, text: str) -> None:
        print(text, file=self.err)

    def _interactive_reauth(self) -> Tuple[str, str]:
        """Prompt user to re-authenticate when session expires (error codes 703/704)."""
        self._print_err("\n[!] Session expired or logged out by another client. Re-authentication required.")
        default_user = self.client.session.username or "admin"
        user_in = self.input_fn(f"Username [{default_user}]: ").strip()
        username = user_in or default_user
        password = self.password_fn("Password: ")
        return username, password

    def prompt_login(self, username: Optional[str] = None) -> bool:
        """Interactively prompt for username and password and authenticate."""
        if not username:
            default_user = self.client.session.username or "admin"
            user_in = self.input_fn(f"Username [{default_user}]: ").strip()
            username = user_in or default_user
        password = self.password_fn("Password: ")
        if not password:
            raise ValidationError("Password cannot be empty.")
        self.client.login(username, password)
        return True

    def confirm_action(
        self,
        summary: str,
        warning: Optional[str] = None,
        force_yes: bool = False,
    ) -> bool:
        """Require explicit user confirmation before executing a configuration or destructive command."""
        if self.auto_confirm or force_yes:
            return True
        if warning:
            self._print_err(f"\n[!] WARNING: {warning}")
        ans = self.input_fn(f"[?] Confirm operation: {summary} [y/N]: ").strip().lower()
        if ans not in ("y", "yes"):
            self._print("[-] Operation cancelled.")
            return False
        return True

    def ensure_authenticated(self) -> None:
        """Verify that the session is authenticated before running an `/admin/*` command."""
        if not self.client.session.is_authenticated:
            raise PermissionDeniedError(
                "Not authenticated. Run 'login' first (or 'probe' for unauthenticated pre-login status)."
            )

    def dispatch_tokens(self, tokens: List[str]) -> int:
        """Dispatch a tokenized command and print human-readable or JSON output. Returns exit code (0=ok, 1=error)."""
        if not tokens:
            return 0

        # Check global flags anywhere in token list for convenience
        use_json = self.default_json or ("--json" in tokens) or ("-j" in tokens)
        force_yes = self.auto_confirm or ("--yes" in tokens) or ("-y" in tokens)
        filtered = [t for t in tokens if t not in ("--json", "-j", "--yes", "-y")]

        if not filtered:
            return 0

        cmd_word = filtered[0].lower()
        args = filtered[1:]

        try:
            if cmd_word in ("help", "?"):
                self._print(HELP_TEXT)
                return 0

            if cmd_word == "probe":
                return self._cmd_probe(args, use_json)

            if cmd_word == "connect":
                return self._cmd_connect(args, use_json)

            if cmd_word == "login":
                return self._cmd_login(args, use_json)

            if cmd_word == "logout":
                return self._cmd_logout(args, use_json)

            if cmd_word == "status":
                self.ensure_authenticated()
                data = get_system_status(self.client)
                self._print(format_json(data) if use_json else render_status(data))
                return 0

            if cmd_word == "interfaces":
                self.ensure_authenticated()
                if args and args[0].lower() == "stats":
                    stats = get_switch_port_statistics(self.client)
                    if use_json:
                        self._print(format_json(stats))
                    else:
                        rows = [
                            [
                                f"Port {p.get('port')}",
                                p.get("rx_All") or p.get("rx_Normal"),
                                p.get("rx_Unicast", "---"),
                                p.get("rx_Broad", "---"),
                                p.get("tx_All") or p.get("tx_Normal"),
                                p.get("tx_Unicast", "---"),
                                p.get("tx_Broad", "---"),
                            ]
                            for p in stats
                        ]
                        self._print(
                            render_table(
                                ["Port", "RX Total", "RX Unicast", "RX Broadcast", "TX Total", "TX Unicast", "TX Broadcast"],
                                rows,
                                title="Switch Port Packet Statistics",
                            )
                        )
                    return 0
                data = get_interfaces_overview(self.client)
                self._print(format_json(data) if use_json else render_interfaces(data))
                return 0

            if cmd_word == "interface":
                self.ensure_authenticated()
                return self._cmd_interface_control(args, use_json, force_yes)

            if cmd_word == "devices":
                self.ensure_authenticated()
                data = get_connected_devices(self.client)
                self._print(format_json(data) if use_json else render_devices(data))
                return 0

            if cmd_word == "device":
                self.ensure_authenticated()
                return self._cmd_device_control(args, use_json, force_yes)

            if cmd_word == "dhcp":
                self.ensure_authenticated()
                return self._cmd_dhcp(args, use_json, force_yes)

            if cmd_word == "vlans":
                self.ensure_authenticated()
                data = get_vlans(self.client)
                self._print(format_json(data) if use_json else render_vlans(data))
                return 0

            if cmd_word == "vlan":
                self.ensure_authenticated()
                return self._cmd_vlan(args, use_json, force_yes)

            if cmd_word == "routes":
                self.ensure_authenticated()
                data = get_all_routes(self.client)
                self._print(format_json(data) if use_json else render_routes(data))
                return 0

            if cmd_word == "route":
                self.ensure_authenticated()
                return self._cmd_route(args, use_json, force_yes)

            if cmd_word == "firewall":
                self.ensure_authenticated()
                return self._cmd_firewall(args, use_json, force_yes)

            if cmd_word == "vpn":
                self.ensure_authenticated()
                if not args or args[0].lower() == "status":
                    data = get_vpn_status(self.client)
                    self._print(format_json(data) if use_json else render_vpn_status(data))
                    return 0
                raise ValidationError("Usage: vpn status")

            if cmd_word == "traffic":
                self.ensure_authenticated()
                data = get_traffic_overview(self.client)
                self._print(format_json(data) if use_json else render_traffic(data))
                return 0

            if cmd_word == "logs":
                self.ensure_authenticated()
                return self._cmd_logs(args, use_json, force_yes)

            if cmd_word == "config":
                self.ensure_authenticated()
                return self._cmd_config(args, use_json, force_yes)

            if cmd_word in ("ssh", "telnet"):
                raise UnsupportedFeatureError(
                    f"'{cmd_word}' management is disabled by default in ER605 v1.3.2 firmware "
                    "(/etc/config/dropbear has ssh_port_switch='off', /etc/init.d/telnet is commented out, "
                    "and /etc/init.d/dropbear dynamically overwrites the root password with an MD5 hash of the MAC). "
                    "Use this HTTP/HTTPS RPC CLI instead."
                )

            if cmd_word in ("wifi", "wireless", "wlan"):
                raise UnsupportedFeatureError(
                    "The TP-Link ER605 v1.0 is a wired-only multi-WAN gateway (firmware reports radio=0). "
                    "Wireless configuration is not supported on this hardware."
                )

            if cmd_word in ("reset", "factory-reset", "reboot"):
                raise UnsupportedFeatureError(
                    f"'{cmd_word}' is restricted by CLI safety policy to prevent accidental router lockout or factory wipe."
                )

            raise ValidationError(f"Unknown command '{cmd_word}'. Type 'help' to list supported commands.")

        except ER605Error as exc:
            if use_json:
                err_payload: Dict[str, Any] = {
                    "error": True,
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
                if hasattr(exc, "error_code") and getattr(exc, "error_code"):
                    err_payload["error_code"] = getattr(exc, "error_code")
                self._print(format_json(err_payload))
            else:
                self._print_err(f"[-] {type(exc).__name__}: {exc}")
            return 1

    def _cmd_probe(self, args: List[str], use_json: bool) -> int:
        info = self.client.probe_prelogin_info()
        rsa_available = False
        modulus_bits = 0
        try:
            n_hex, _ = self.client.fetch_rsa_keys()
            rsa_available = True
            modulus_bits = len(n_hex) * 4
        except ER605Error:
            pass

        probe_data = {
            "host": self.client.session.host,
            "base_url": self.client.session.base_url,
            "reachable": True,
            "model": info.get("locale", {}).get("model"),
            "locale": info.get("locale", {}).get("locale"),
            "multiwan": info.get("locale", {}).get("multiwan"),
            "radio": info.get("locale", {}).get("radio"),
            "config_state": info.get("config_state"),
            "rsa_login_key_available": rsa_available,
            "rsa_modulus_bits": modulus_bits,
        }
        if use_json:
            self._print(format_json(probe_data))
        else:
            cfg = probe_data["config_state"] or {}
            rows = [
                ("Router URL", probe_data["base_url"]),
                ("Reachable", "Yes"),
                ("Model", probe_data["model"]),
                ("Locale", probe_data["locale"]),
                ("Multi-WAN Support", probe_data["multiwan"]),
                ("Wireless Radio", probe_data["radio"]),
                ("Config Status", cfg.get("status")),
                ("Default Password State", cfg.get("dft_pwd_status")),
                ("HTTPS Redirect", f"{cfg.get('redirect_https')} (port {cfg.get('https_port')})"),
                ("RSA Login Key Ready", f"Yes ({modulus_bits}-bit)" if rsa_available else "No"),
            ]
            self._print(render_table(["Property", "Value"], rows, title="ER605 Pre-Login Probe"))
        return 0

    def _cmd_connect(self, args: List[str], use_json: bool) -> int:
        pos, val_flags, bool_flags = parse_flag_options(
            args,
            allowed_value_flags=("--scheme", "--port", "--ca-cert"),
            allowed_bool_flags=("--insecure", "-k"),
        )
        if not pos:
            raise ValidationError("Usage: connect <host> [--scheme http|https] [--port <port>] [--insecure]")
        host = pos[0]
        scheme = val_flags.get("--scheme", self.client.session.scheme)
        if scheme not in ("http", "https"):
            raise ValidationError("--scheme must be 'http' or 'https'.")
        port = int(val_flags["--port"]) if "--port" in val_flags else None
        verify_tls = not (bool_flags.get("--insecure") or bool_flags.get("-k"))
        ca_file = val_flags.get("--ca-cert")

        self.client.configure_target(
            host=host,
            scheme=scheme,
            port=port,
            verify_tls=verify_tls,
            ca_file=ca_file,
        )
        info = self.client.probe_prelogin_info()
        model = info.get("locale", {}).get("model", "ER605")
        if use_json:
            self._print(
                format_json(
                    {
                        "connected": True,
                        "base_url": self.client.session.base_url,
                        "model": model,
                    }
                )
            )
        else:
            self._print(f"[+] Target set to {self.client.session.base_url} (Detected: {model}). Run 'login' to authenticate.")
        return 0

    def _cmd_login(self, args: List[str], use_json: bool) -> int:
        username = args[0] if args else None
        self.prompt_login(username=username)
        if use_json:
            self._print(
                format_json(
                    {
                        "authenticated": True,
                        "host": self.client.session.host,
                        "username": self.client.session.username,
                    }
                )
            )
        else:
            self._print("[+] Authenticated successfully.")
        return 0

    def _cmd_logout(self, args: List[str], use_json: bool) -> int:
        self.client.logout()
        if use_json:
            self._print(format_json({"authenticated": False, "logged_out": True}))
        else:
            self._print("[+] Logged out cleanly.")
        return 0

    def _cmd_interface_control(self, args: List[str], use_json: bool, force_yes: bool) -> int:
        if not args or args[0].lower() not in ("connect", "disconnect", "port"):
            raise ValidationError(
                "Usage:\n"
                "  interface <connect|disconnect> <1..5 or WAN1..WAN4>\n"
                "  interface port <1..5> <on|off> [--flowcontrol on|off] [--speed auto|1000MF|100MF|100MH|10MF|10MH]"
            )
        action = args[0].lower()
        if action == "port":
            pos, val_flags, _ = parse_flag_options(
                args[1:],
                allowed_value_flags=("--flowcontrol", "--speed", "--mode"),
            )
            if len(pos) < 2:
                raise ValidationError(
                    "Usage: interface port <1..5> <on|off> [--flowcontrol on|off] [--speed auto|1000MF|100MF|100MH|10MF|10MH]"
                )
            port_num = int(pos[0])
            state_val = "on" if pos[1].lower() in ("on", "up", "enable", "1") else "off"
            fc = val_flags.get("--flowcontrol")
            speed = val_flags.get("--speed") or val_flags.get("--mode")
            warning = (
                f"Powering down physical Port {port_num} will immediately sever the link if your management PC or uplink switch is plugged into Port {port_num}!"
                if state_val == "off"
                else None
            )
            if not self.confirm_action(
                f"Set physical switch Port {port_num} admin state={state_val}",
                warning=warning,
                force_yes=force_yes,
            ):
                return 0
            res = set_switch_port_params(
                self.client,
                port=port_num,
                state=state_val,
                flowcontrol=fc,
                negotiation_mode=speed,
            )
            if use_json:
                self._print(format_json(res))
            else:
                self._print(f"[+] Updated physical Switch Port {port_num}: {res['updated']}")
            return 0

        if len(args) < 2:
            raise ValidationError("Usage: interface <connect|disconnect> <1..5 or WAN1..WAN4>")
        wan_id = args[1]
        warning = (
            f"Disconnecting {wan_id} will interrupt connectivity on {wan_id} (and will sever your session if your PC is plugged into Port {wan_id})."
            if action == "disconnect"
            else None
        )
        if not self.confirm_action(f"{action.upper()} interface {wan_id}", warning=warning, force_yes=force_yes):
            return 0
        if action == "connect":
            res = connect_wan_interface(self.client, wan_id)
        else:
            res = disconnect_wan_interface(self.client, wan_id)
        if use_json:
            self._print(format_json(res))
        else:
            self._print(f"[+] Successfully triggered '{action}' on {res.get('target', wan_id)} ({res.get('mode', '')}).")
        return 0

    def _cmd_device_control(self, args: List[str], use_json: bool, force_yes: bool) -> int:
        if not args or args[0].lower() not in ("block", "unblock", "filter"):
            raise ValidationError(
                "Usage:\n"
                "  device block [<rule_name>] <mac_address>\n"
                "  device unblock <rule_name_or_mac>\n"
                "  device filter <on|off> [--mode black|white] [--zone WAN|ALL]"
            )
        sub = args[0].lower()
        if sub == "block":
            if len(args) == 2:
                mac = args[1]
                clean_hex = mac.replace(":", "").replace("-", "").upper()
                name = f"Block_{clean_hex}"
            elif len(args) >= 3:
                name, mac = args[1], args[2]
            else:
                raise ValidationError("Usage: device block [<rule_name>] <mac_address>")

            if not self.confirm_action(
                f"Add MAC filter rule '{name}' ({mac})",
                warning="Blocking your own workstation's MAC address when MAC filtering is enabled in black (deny) mode will lock you out of the router.",
                force_yes=force_yes,
            ):
                return 0
            res = add_mac_filter_rule(self.client, name, mac)
            mf_state = get_mac_filtering(self.client).get("settings", {})
            if use_json:
                self._print(
                    format_json(
                        {
                            "action": "device_block",
                            "name": name,
                            "mac": mac,
                            "mac_filter_settings": mf_state,
                            "result": res,
                        }
                    )
                )
            else:
                self._print(f"[+] Added MAC filter rule '{name}' ({mac}).")
                if mf_state.get("enable") != "on":
                    self._print(
                        "[!] Note: Global MAC filtering is currently 'off'. "
                        "To actively enforce the block list on internet traffic, run: device filter on --mode black --zone WAN"
                    )
            return 0

        if sub == "unblock":
            if len(args) < 2:
                raise ValidationError("Usage: device unblock <rule_name_or_mac>")
            ident = args[1]
            if not self.confirm_action(f"Remove MAC filter rule '{ident}'", force_yes=force_yes):
                return 0
            res = delete_mac_filter_rule(self.client, ident)
            if use_json:
                self._print(format_json({"action": "device_unblock", "target": ident, "result": res}))
            else:
                self._print(f"[+] Removed MAC filter rule '{ident}'.")
            return 0

        # sub == "filter"
        pos, val_flags, _ = parse_flag_options(
            args[1:],
            allowed_value_flags=("--mode", "--zone"),
        )
        if not pos or pos[0].lower() not in ("on", "off", "enable", "disable"):
            raise ValidationError("Usage: device filter <on|off> [--mode black|white] [--zone WAN|ALL]")
        en_arg = "on" if pos[0].lower() in ("on", "enable") else "off"
        cur_settings = get_mac_filtering(self.client).get("settings", {})
        mode = val_flags.get("--mode", cur_settings.get("filter_mode") or "black")
        zone = val_flags.get("--zone", cur_settings.get("interfaces") or "WAN")
        warning = (
            "Enabling MAC filtering in 'white' (allow-only) mode or 'ALL' zone can immediately disconnect your management session if your MAC is not allowed!"
            if en_arg == "on" and (mode == "white" or zone.upper() == "ALL")
            else None
        )
        if not self.confirm_action(
            f"Set global MAC filtering to enable={en_arg}, mode={mode}, zone={zone}",
            warning=warning,
            force_yes=force_yes,
        ):
            return 0
        res = set_mac_filtering_mode(self.client, enable=en_arg, filter_mode=mode, interfaces=zone)
        if use_json:
            self._print(
                format_json({"action": "device_filter_mode", "enable": en_arg, "mode": mode, "zone": zone, "result": res})
            )
        else:
            self._print(f"[+] Updated global MAC filtering: enable={en_arg}, mode={mode}, zone={zone}.")
        return 0

    def _cmd_dhcp(self, args: List[str], use_json: bool, force_yes: bool) -> int:
        if not args:
            raise ValidationError(
                "Usage:\n"
                "  dhcp leases\n"
                "  dhcp reservations\n"
                "  dhcp server\n"
                "  dhcp reservation <add|update|delete> ..."
            )
        sub = args[0].lower()
        if sub == "leases":
            leases = get_dhcp_leases(self.client)
            self._print(format_json(leases) if use_json else render_dhcp_leases(leases))
            return 0
        if sub == "reservations":
            resv = get_dhcp_reservations(self.client)
            self._print(format_json(resv) if use_json else render_dhcp_reservations(resv))
            return 0
        if sub == "server":
            lan = get_lan_dhcp_settings(self.client)
            self._print(format_json(lan) if use_json else render_dhcp_server(lan))
            return 0
        if sub == "reservation":
            if len(args) < 2:
                raise ValidationError("Usage: dhcp reservation <list|add|update|delete> ...")
            action = args[1].lower()
            rest = args[2:]
            if action == "list":
                resv = get_dhcp_reservations(self.client)
                self._print(format_json(resv) if use_json else render_dhcp_reservations(resv))
                return 0
            if action == "add":
                pos, val_flags, _ = parse_flag_options(
                    rest,
                    allowed_value_flags=("--interface", "--note", "--enable", "--bind"),
                )
                if len(pos) < 2:
                    raise ValidationError(
                        "Usage: dhcp reservation add <ip> <mac> [--interface LAN] [--note <text>] [--bind on|off] [--enable on|off]"
                    )
                ip_addr, mac_addr = pos[0], pos[1]
                iface = val_flags.get("--interface", "LAN")
                note = val_flags.get("--note", "")
                enable = val_flags.get("--enable", "on")
                bind = val_flags.get("--bind", "off")
                if not self.confirm_action(
                    f"Add static DHCP reservation {ip_addr} -> {mac_addr} on {iface}",
                    force_yes=force_yes,
                ):
                    return 0
                res = add_dhcp_reservation(
                    self.client,
                    ip=ip_addr,
                    mac=mac_addr,
                    interface=iface,
                    note=note,
                    enable=enable,
                    bind=bind,
                )
                if use_json:
                    self._print(format_json({"action": "dhcp_reservation_add", "ip": ip_addr, "mac": mac_addr, "result": res}))
                else:
                    self._print(f"[+] Created DHCP reservation {ip_addr} ({mac_addr}) on {iface}.")
                return 0

            if action == "update":
                pos, val_flags, _ = parse_flag_options(
                    rest,
                    allowed_value_flags=("--new-ip", "--mac", "--interface", "--note", "--enable", "--bind"),
                )
                if not pos:
                    raise ValidationError(
                        "Usage: dhcp reservation update <target_ip> [--new-ip <ip>] [--mac <mac>] [--interface <if>] [--note <text>] [--bind on|off] [--enable on|off]"
                    )
                target_ip = pos[0]
                if not val_flags:
                    raise ValidationError("Specify at least one field to update (--new-ip, --mac, --interface, --note, --bind, --enable).")
                if not self.confirm_action(
                    f"Update static DHCP reservation {target_ip}",
                    force_yes=force_yes,
                ):
                    return 0
                res = update_dhcp_reservation(
                    self.client,
                    target_ip=target_ip,
                    new_ip=val_flags.get("--new-ip"),
                    new_mac=val_flags.get("--mac"),
                    interface=val_flags.get("--interface"),
                    note=val_flags.get("--note"),
                    enable=val_flags.get("--enable"),
                    bind=val_flags.get("--bind"),
                )
                if use_json:
                    self._print(format_json({"action": "dhcp_reservation_update", "target_ip": target_ip, "result": res}))
                else:
                    self._print(f"[+] Updated DHCP reservation for {target_ip}.")
                return 0

            if action == "delete":
                if not rest:
                    raise ValidationError("Usage: dhcp reservation delete <ip>")
                target_ip = rest[0]
                if not self.confirm_action(
                    f"Delete static DHCP reservation for {target_ip}",
                    force_yes=force_yes,
                ):
                    return 0
                res = delete_dhcp_reservation(self.client, target_ip)
                if use_json:
                    self._print(format_json({"action": "dhcp_reservation_delete", "ip": target_ip, "result": res}))
                else:
                    self._print(f"[+] Deleted DHCP reservation for {target_ip}.")
                return 0

        raise ValidationError(f"Unknown dhcp subcommand '{sub}'. Expected: leases, reservations, server, reservation.")

    def _cmd_vlan(self, args: List[str], use_json: bool, force_yes: bool) -> int:
        if not args or args[0].lower() == "list":
            data = get_vlans(self.client)
            self._print(format_json(data) if use_json else render_vlans(data))
            return 0

        sub = args[0].lower()
        rest = args[1:]

        if sub == "show":
            if not rest:
                raise ValidationError("Usage: vlan show <vlan_id>")
            v = get_vlan_by_id(self.client, rest[0])
            if use_json:
                self._print(format_json(v))
            else:
                rows = [
                    ("VLAN ID", v.get("vlan")),
                    ("Name", v.get("name")),
                    ("Ports", format_vlan_ports(v.get("ports", ""))),
                    ("Raw Port String", v.get("ports")),
                    ("Used By", v.get("users") or "custom"),
                    ("Description", v.get("desc") or "---"),
                ]
                self._print(render_table(["Field", "Value"], rows, title=f"VLAN {v.get('vlan')} Details"))
            return 0

        if sub == "create":
            pos, val_flags, _ = parse_flag_options(rest, allowed_value_flags=("--desc",))
            if len(pos) < 3:
                raise ValidationError(
                    "Usage: vlan create <vlan_id> <name> <ports> [--desc <text>]\n"
                    "Example: vlan create 20 Guest_VLAN '2:u,3:t' --desc 'Guest segment'"
                )
            vid = int(pos[0])
            name = pos[1]
            ports_spec = pos[2]
            desc = val_flags.get("--desc", pos[3] if len(pos) > 3 else "")
            if not self.confirm_action(
                f"Create 802.1Q VLAN {vid} ('{name}') on ports '{ports_spec}'",
                warning="Changing switch port VLAN memberships can disrupt connectivity on those physical ports.",
                force_yes=force_yes,
            ):
                return 0
            res = create_vlan(self.client, vlan_id=vid, name=name, ports_spec=ports_spec, desc=desc)
            if use_json:
                self._print(format_json({"action": "vlan_create", "vlan_id": vid, "name": name, "result": res}))
            else:
                self._print(f"[+] Created 802.1Q VLAN {vid} ('{name}').")
            return 0

        if sub == "update":
            pos, val_flags, _ = parse_flag_options(
                rest,
                allowed_value_flags=("--name", "--ports", "--desc"),
            )
            if not pos:
                raise ValidationError("Usage: vlan update <vlan_id> [--name <name>] [--ports <ports>] [--desc <text>]")
            vid = int(pos[0])
            if not val_flags:
                raise ValidationError("Specify at least one option to update (--name, --ports, --desc).")
            if not self.confirm_action(
                f"Update 802.1Q VLAN {vid}",
                warning="Modifying VLAN port memberships may disconnect active devices on those ports.",
                force_yes=force_yes,
            ):
                return 0
            res = update_vlan(
                self.client,
                vlan_id=vid,
                name=val_flags.get("--name"),
                ports_spec=val_flags.get("--ports"),
                desc=val_flags.get("--desc"),
            )
            if use_json:
                self._print(format_json({"action": "vlan_update", "vlan_id": vid, "result": res}))
            else:
                self._print(f"[+] Updated 802.1Q VLAN {vid}.")
            return 0

        if sub == "delete":
            if not rest:
                raise ValidationError("Usage: vlan delete <vlan_id>")
            vid = int(rest[0])
            if not self.confirm_action(
                f"Delete 802.1Q VLAN {vid}",
                warning="Deleting an active VLAN will sever traffic for any tagged/untagged hosts on that VLAN.",
                force_yes=force_yes,
            ):
                return 0
            res = delete_vlan(self.client, vlan_id=vid)
            if use_json:
                self._print(format_json({"action": "vlan_delete", "vlan_id": vid, "result": res}))
            else:
                self._print(f"[+] Deleted 802.1Q VLAN {vid}.")
            return 0

        raise ValidationError(f"Unknown vlan subcommand '{sub}'. Expected: list, show, create, update, delete.")

    def _cmd_route(self, args: List[str], use_json: bool, force_yes: bool) -> int:
        if not args or args[0].lower() == "list":
            data = get_all_routes(self.client)
            self._print(format_json(data) if use_json else render_routes(data))
            return 0

        sub = args[0].lower()
        rest = args[1:]

        if sub == "add":
            pos, val_flags, _ = parse_flag_options(
                rest,
                allowed_value_flags=("--interface", "--metric", "--note", "--enable"),
            )
            if len(pos) < 4:
                raise ValidationError(
                    "Usage: route add <name> <target_ip> <netmask> <gateway> [--interface WAN1] [--metric 0] [--note <text>]"
                )
            name, target, netmask, gateway = pos[0], pos[1], pos[2], pos[3]
            iface = val_flags.get("--interface", "WAN1")
            metric = int(val_flags.get("--metric", "0"))
            note = val_flags.get("--note", "")
            enable = val_flags.get("--enable", "on")
            if not self.confirm_action(
                f"Add static route '{name}' ({target}/{netmask} via {gateway} on {iface})",
                warning="An incorrect static route overlapping your management subnet can make the router unreachable.",
                force_yes=force_yes,
            ):
                return 0
            res = add_static_route(
                self.client,
                name=name,
                target=target,
                netmask=netmask,
                gateway=gateway,
                interface=iface,
                metric=metric,
                note=note,
                enable=enable,
            )
            if use_json:
                self._print(format_json({"action": "route_add", "name": name, "result": res}))
            else:
                self._print(f"[+] Added static route '{name}'.")
            return 0

        if sub == "delete":
            if not rest:
                raise ValidationError("Usage: route delete <name_or_key>")
            ident = rest[0]
            if not self.confirm_action(
                f"Delete static route '{ident}'",
                warning="Deleting a route used to reach your management station will disconnect this session.",
                force_yes=force_yes,
            ):
                return 0
            res = delete_static_route(self.client, ident)
            if use_json:
                self._print(format_json({"action": "route_delete", "target": ident, "result": res}))
            else:
                self._print(f"[+] Deleted static route '{ident}'.")
            return 0

        raise ValidationError(f"Unknown route subcommand '{sub}'. Expected: list, add, delete.")

    def _cmd_firewall(self, args: List[str], use_json: bool, force_yes: bool) -> int:
        if not args or args[0].lower() == "rules":
            data = get_firewall_overview(self.client)
            self._print(format_json(data) if use_json else render_firewall(data))
            return 0

        sub = args[0].lower()
        rest = args[1:]

        if sub == "acl":
            if not rest:
                raise ValidationError("Usage: firewall acl <list|add|delete> ...")
            action = rest[0].lower()
            acl_args = rest[1:]
            if action == "list":
                data = get_firewall_overview(self.client)
                self._print(format_json(data["acl_rules"]) if use_json else render_firewall(data))
                return 0
            if action == "add":
                pos, val_flags, _ = parse_flag_options(
                    acl_args,
                    allowed_value_flags=("--zone", "--service", "--src", "--dest", "--time"),
                )
                if len(pos) < 2:
                    raise ValidationError(
                        "Usage: firewall acl add <name> <ACCEPT|DROP> [--zone LAN] [--service ALL] [--src IPGROUP_ANY] [--dest IPGROUP_ANY] [--time Any]"
                    )
                name, policy = pos[0], pos[1].upper()
                zones = [z.strip() for z in val_flags.get("--zone", "LAN").split(",") if z.strip()]
                service = val_flags.get("--service", "ALL")
                src = val_flags.get("--src", "IPGROUP_ANY")
                dest = val_flags.get("--dest", "IPGROUP_ANY")
                time_obj = val_flags.get("--time", "Any")
                warning = (
                    "Adding a broad DROP rule on LAN or ALL zones with IPGROUP_ANY can immediately block management access to the router!"
                    if policy == "DROP"
                    else None
                )
                if not self.confirm_action(
                    f"Add ACL rule '{name}' ({policy} service={service} zone={','.join(zones)} src={src} dest={dest})",
                    warning=warning,
                    force_yes=force_yes,
                ):
                    return 0
                res = add_acl_rule(
                    self.client,
                    name=name,
                    policy=policy,
                    service=service,
                    zones=zones,
                    src=src,
                    dest=dest,
                    time_obj=time_obj,
                )
                if use_json:
                    self._print(format_json({"action": "acl_add", "name": name, "policy": policy, "result": res}))
                else:
                    self._print(f"[+] Created ACL rule '{name}' ({policy}).")
                return 0

            if action == "delete":
                if not acl_args:
                    raise ValidationError("Usage: firewall acl delete <name_or_key>")
                ident = acl_args[0]
                if not self.confirm_action(f"Delete ACL rule '{ident}'", force_yes=force_yes):
                    return 0
                res = delete_acl_rule(self.client, ident)
                if use_json:
                    self._print(format_json({"action": "acl_delete", "target": ident, "result": res}))
                else:
                    self._print(f"[+] Deleted ACL rule '{ident}'.")
                return 0

        raise ValidationError("Usage: firewall rules | firewall acl <list|add|delete> ...")

    def _cmd_logs(self, args: List[str], use_json: bool, force_yes: bool) -> int:
        if args and args[0].lower() == "clear":
            if not self.confirm_action("Clear all router system logs", force_yes=force_yes):
                return 0
            res = clear_system_logs(self.client)
            if use_json:
                self._print(format_json(res))
            else:
                self._print("[+] All system logs cleared.")
            return 0

        page_num = int(args[0]) if len(args) >= 1 else 1
        page_size = int(args[1]) if len(args) >= 2 else 50
        data = get_system_logs(self.client, page_num=page_num, page_size=page_size)
        self._print(format_json(data) if use_json else render_logs(data))
        return 0

    def _cmd_config(self, args: List[str], use_json: bool, force_yes: bool) -> int:
        if not args or args[0].lower() == "show":
            section = args[1] if len(args) >= 2 else "all"
            data = get_config_summary(self.client, section=section)
            if use_json:
                self._print(format_json(data))
            else:
                self._print(f"=== ER605 Redacted Configuration ({section}) ===")
                self._print(format_json(data))
            return 0

        if args[0].lower() == "backup":
            if len(args) < 2:
                raise ValidationError("Usage: config backup <output_file_path>")
            out_path = args[1]
            res = save_config_backup(self.client, out_path)
            if use_json:
                self._print(format_json(res))
            else:
                self._print(
                    f"[+] Saved encrypted router configuration backup ({res['bytes']} bytes) to {res['path']}"
                )
            return 0

        raise ValidationError("Usage: config show [all|system|network|dhcp|vlan|firewall|vpn|services] | config backup <path>")


class ER605Shell(cmd.Cmd):
    """Interactive terminal REPL (`er605> `) for manual router inspection and control."""

    prompt = "er605> "

    def __init__(self, dispatcher: CommandDispatcher) -> None:
        super().__init__()
        self.dispatcher = dispatcher

    def preloop(self) -> None:
        """Disable readline history persistence so commands/parameters are not written to disk."""
        try:
            import readline

            readline.clear_history()
        except ImportError:
            pass

    def emptyline(self) -> bool:
        """Do nothing on empty Enter press (do not repeat previous command)."""
        return False

    def default(self, line: str) -> bool:
        """Route all input lines through `CommandDispatcher`."""
        stripped = line.strip()
        if not stripped:
            return False
        if stripped.lower() in ("exit", "quit", "eof"):
            return self.do_exit("")
        try:
            tokens = tokenize_command_line(stripped)
        except ValidationError as exc:
            self.dispatcher._print_err(f"[-] {exc}")
            return False
        self.dispatcher.dispatch_tokens(tokens)
        return False

    def do_help(self, arg: str) -> None:
        """Show supported commands and syntax."""
        self.dispatcher._print(HELP_TEXT)

    def do_exit(self, arg: str) -> bool:
        """Log out cleanly if authenticated and exit the CLI."""
        if self.dispatcher.client.session.is_authenticated:
            try:
                self.dispatcher.client.logout()
                self.dispatcher._print("[+] Session closed cleanly.")
            except ER605Error:
                pass
        return True

    def do_quit(self, arg: str) -> bool:
        """Alias for exit."""
        return self.do_exit(arg)

    def do_EOF(self, arg: str) -> bool:
        """Handle Ctrl-D cleanly."""
        self.dispatcher._print("")
        return self.do_exit(arg)
