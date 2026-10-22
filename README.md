# `er605-cli` — TP-Link ER605 Firmware-Based Router Control CLI

A standalone, modular Python command-line interface for manually inspecting and administering a **TP-Link ER605 (TL-R605) v1** router running firmware `1.3.2 Build 20251030 Rel.16640`.

Built directly from reverse-engineering the extracted firmware's LuCI RPC controllers (`usr/lib/lua/luci/controller/`) and web UI (`www/webpages/`), `er605-cli` uses **only Python's standard library** (zero third-party runtime dependencies) and exposes both an interactive shell (`er605> `) and non-interactive machine-readable JSON commands (`--json`) for future automation or AI agent integration.

---

## Features & Safety Guarantees

- **Zero External Dependencies**: Runs out-of-the-box on Python 3.8+ using standard library modules (`urllib`, `http.cookiejar`, `ssl`, `json`, `cmd`, `argparse`, `getpass`).
- **Native Firmware Protocol**:
  - Implements TP-Link's exact 1024-bit zero-padded textbook RSA password encryption (`src/er605_cli/auth.py`).
  - Automatically supplies the required CSRF `Referer` header (`check_safe_request` in `dispatcher.lua`).
  - Tracks both the URL `stok` token and `sysauth` HTTP cookie in memory, automatically detecting expired sessions (`703`/`704`) and prompting for safe re-authentication.
- **Credential & Secret Protection**:
  - Never accepts plaintext passwords on the command line or writes credentials, `stok` tokens, or `sysauth` cookies to logs, terminal output, or disk history.
  - Redacts sensitive fields (`password`, `psk`, `private_key`, `secret`) in `config show` and `vpn status`.
  - Keeps TLS certificate verification **enabled by default** when `--scheme https` is used.
- **Manual Confirmation & Lockout Warnings**:
  - Every configuration-changing or destructive command requires explicit `[y/N]` confirmation and displays warnings when an operation could sever management access.

---

## Installation & Setup

No third-party packages are required.

```bash
cd "/home/darkingrayleigh/Downloads/ER605(UN)_V1_1.3.2 Build 20251030/er605-cli"
python3 --version   # Python 3.8+
```

Run the unit test suite to verify all modules:

```bash
python3 -m unittest discover -s tests -v
```

---

## Usage

### 1. Pre-Login Connectivity Probe (No Credentials Required)

Verify reachability, hardware model (`ER605 v1.0`), configuration state, and 1024-bit RSA key readiness against the live router:

```bash
python3 er605.py --host 192.168.0.1 probe
python3 er605.py --host 192.168.0.1 --json probe
```

### 2. Interactive Shell (`er605> `)

Start the interactive CLI:

```bash
python3 er605.py --host 192.168.0.1
```

Example interactive session:

```text
$ python3 er605.py --host 192.168.0.1
ER605 CLI
Router: 192.168.0.1 (ER605 v1.0)

Username [admin]: admin
Password: ********

[+] Authenticated successfully.

er605> help
er605> status
er605> interfaces
er605> interfaces stats
er605> devices
er605> dhcp leases
er605> dhcp reservations
er605> dhcp server
er605> vlans
er605> vlan show 1
er605> routes
er605> firewall rules
er605> vpn status
er605> traffic
er605> logs 1 50
er605> config show system
er605> exit
```

### 3. Non-Interactive Single Command Execution

Pass any command directly on the command line (useful for scripting or future controlled integrations):

```bash
# Human-readable table output
python3 er605.py --host 192.168.0.1 -u admin status

# Structured JSON output (prompts for password on stderr, prints pure JSON to stdout)
python3 er605.py --host 192.168.0.1 -u admin --json interfaces
python3 er605.py --host 192.168.0.1 -u admin --json devices
python3 er605.py --host 192.168.0.1 -u admin --json vlans
```

### 4. Configuration & Control Operations

```text
# 802.1Q VLAN Management (ports 1..5, ':u' untagged, ':t' tagged)
er605> vlan list
er605> vlan show 20
er605> vlan create 20 Guest_VLAN "2:u,3:t" --desc "Guest Network"
er605> vlan update 20 --name Guest_WiFi --ports "2:u,3:t,4:u"
er605> vlan delete 20

# Static DHCP Reservations
er605> dhcp reservation add 192.168.0.50 AA-BB-CC-11-22-33 --interface LAN --note "NAS" --bind on
er605> dhcp reservation update 192.168.0.50 --note "Primary-NAS"
er605> dhcp reservation delete 192.168.0.50

# Firewall Access Control (ACL) Rules
er605> firewall acl add Block_IoT_WAN DROP --zone LAN --service ALL --src IPGROUP_ANY --dest IPGROUP_ANY
er605> firewall acl delete Block_IoT_WAN

# Device MAC Filtering (Block / Unblock)
er605> device block Unknown_Host 22-33-44-55-66-77
er605> device unblock 22-33-44-55-66-77

# Static Routing
er605> route add Branch_LAN 10.20.0.0 255.255.255.0 192.168.0.254 --interface LAN --metric 1
er605> route delete Branch_LAN

# WAN Link Control & Encrypted Config Backup
er605> interface connect WAN1
er605> interface disconnect WAN1
er605> config backup ./er605-backup.bin
er605> logs clear
```

---

## Project Structure

```text
er605-cli/
├── er605.py                        # Executable CLI entry point
├── requirements.txt                # Zero third-party dependencies (stdlib only)
├── README.md                       # Setup and usage guide
├── .gitignore                      # Excludes credentials, backups, and caches
├── config/                         # Local configuration directory
├── src/
│   └── er605_cli/
│       ├── __init__.py
│       ├── auth.py                 # Zero-padded textbook RSA encryption ($.su.encrypt)
│       ├── session.py              # Session state (stok + sysauth cookie jar)
│       ├── client.py               # HTTP/HTTPS LuCI RPC client & CSRF Referer handler
│       ├── commands.py             # Interactive REPL (er605>) & CommandDispatcher
│       ├── parser.py               # CLI arg parser & shell tokenizer
│       ├── output.py               # ASCII table & JSON formatters
│       ├── exceptions.py           # Exception hierarchy & firmware error code catalogue
│       └── operations/             # Reusable programmatic router operations
│           ├── __init__.py
│           ├── system.py           # Status, logs, redacted config, binary backup
│           ├── interfaces.py       # WAN/LAN interfaces, switch state, WAN connect/disconnect
│           ├── dhcp.py             # Connected devices (ARP+DHCP), leases, reservations, LAN DHCP
│           ├── vlan.py             # 802.1Q VLAN list/show/create/update/delete
│           ├── routing.py          # System routes, static route list/add/delete, policy routes
│           ├── firewall.py         # ACL rules, DoS/flood defense, MAC filter, IP-MAC bind, NAT
│           ├── vpn.py              # IPsec, OpenVPN, WireGuard, L2TP, PPTP status
│           └── traffic.py          # Interface, per-IP, and switch port traffic statistics
├── tests/
│   └── test_er605_cli.py           # Unit & protocol simulation test suite
└── docs/
    ├── firmware-analysis.md        # Firmware reverse-engineering report & evidence
    └── api-catalogue.md            # Detailed endpoint & command reference
```
