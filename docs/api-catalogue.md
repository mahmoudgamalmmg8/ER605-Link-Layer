# ER605 CLI — Command & Endpoint Catalogue

Every command implemented in `er605-cli` maps directly to verified LuCI controllers in `usr/lib/lua/luci/controller/` and frontend pages in `www/webpages/pages/userrpm/`.

---

## 1. Session & Authentication Commands

### `probe`
- **What it does**: Checks router reachability, hardware model, locale, multi-WAN capability, configuration state, and 1024-bit RSA login public key readiness.
- **Router Endpoints**:
  - `POST /cgi-bin/luci/;stok=/locale?form=lang` (`operation=read`)
  - `POST /cgi-bin/luci/;stok=/userconfig?form=cfg_save` (`method=get`)
  - `POST /cgi-bin/luci/;stok=/login?form=login` (`method=get`)
- **Required Permissions**: None (pre-login public endpoints).
- **Example Syntax**:
  ```text
  er605> probe
  $ python3 er605.py --host 192.168.0.1 probe
  ```
- **Example Output**:
  ```text
  === ER605 Pre-Login Probe ===
  Property                Value             
  ----------------------  ------------------
  Router URL              http://192.168.0.1
  Reachable               Yes               
  Model                   ER605 v1.0        
  Locale                  en_US             
  Multi-WAN Support       1                 
  Wireless Radio          0                 
  Config Status           Saved             
  Default Password State  Modify            
  HTTPS Redirect          on (port 443)     
  RSA Login Key Ready     Yes (1024-bit)    
  ```
- **Verification Status**: **Tested live against actual router (`192.168.0.1`)** and unit-tested.

---

### `connect`
- **What it does**: Reconfigures the target router IP/hostname, scheme (`http`/`https`), port, and TLS verification settings, then probes the router.
- **Router Endpoints**: `/locale?form=lang`, `/userconfig?form=cfg_save`
- **Required Permissions**: None.
- **Example Syntax**:
  ```text
  er605> connect 192.168.0.1 --scheme http
  ```
- **Example Output**:
  ```text
  [+] Target set to http://192.168.0.1 (Detected: ER605 v1.0). Run 'login' to authenticate.
  ```
- **Verification Status**: **Tested live against actual router (`192.168.0.1`)** and unit-tested.

---

### `login` / `logout` / `exit`
- **What they do**:
  - `login [username]`: Prompts securely for password without echoing, fetches the router's RSA public key, encrypts the password via zero-padded RSA, authenticates, and stores `stok` + `sysauth` in memory.
  - `logout`: Invalidates the server-side session and clears in-memory credentials.
  - `exit` / `quit`: Logs out cleanly if authenticated and exits the shell.
- **Router Endpoints**:
  - `POST /cgi-bin/luci/;stok=/login?form=login` (`method=get` & `method=login`)
  - `POST /cgi-bin/luci/;stok=<stok>/admin/system?form=logout` (`method=get`)
- **Required Permissions**: Administrator credentials (`login`); active session (`logout`).
- **Example Syntax**:
  ```text
  er605> login admin
  Password: ********
  [+] Authenticated successfully.
  er605> logout
  [+] Logged out cleanly.
  ```
- **Verification Status**: RSA public key retrieval (`/login?form=login`, `method=get`) **tested live against `192.168.0.1`**; full login/logout/reauth handshake verified via firmware-accurate unit tests (live router has user-modified password `dft_pwd_status: "Modify"`).

---

## 2. Read-Only Inspection Commands

### `status`
- **What it does**: Retrieves router model, hardware version, firmware build, system clock, formatted uptime, per-core CPU load, memory usage, and configuration state.
- **Router Endpoints**:
  - `/locale?form=lang` (`operation=read`)
  - `/userconfig?form=cfg_save` (`method=get`)
  - `/admin/firmware?form=upgrade` (`method=get`)
  - `/admin/status?form=version` (`method=get`)
  - `/admin/status?form=time_run` (`method=get`)
  - `/admin/sys_status?form=all_usage` (`method=get`)
- **Required Permissions**: Authenticated session (`stok` + `sysauth`).
- **Example Syntax**:
  ```text
  er605> status
  er605> status --json
  ```
- **Example Output**:
  ```text
  === ER605 System Status ===
  Property          Value                            
  ----------------  ---------------------------------
  Router Address    192.168.0.1                      
  Model             ER605                            
  Hardware Version  ER605 v1.0                       
  Firmware Version  1.3.2 Build 20251030 Rel.16640   
  System Time       2026-10-22 22:00:00              
  Uptime            4d 11h 25m 9s                    
  CPU Load          core1: 8%, core2: 5%             
  Memory Usage      34%                              
  Config State      Saved                            
  HTTPS Redirect    on (port 443)                    
  ```
- **Verification Status**: Verified against firmware controllers (`status.lua`, `sys_status.lua`, `firmware.lua`) and unit tests.

---

### `interfaces [stats]`
- **What it does**: Displays WAN mode, WAN/LAN logical interface status (IP, netmask, gateway, MAC, DNS, link state), VPN tunnel interfaces, and physical switch port link states (`speed`, `duplex`, `flowcontrol`). Passing `stats` displays per-port packet counters.
- **Router Endpoints**:
  - `/admin/interface_wan?form=wanmode` (`method=get`)
  - `/admin/interface?form=status2` (`method=get`)
  - `/admin/switch?form=state` (`method=get`)
  - `/admin/switch?form=statistic` (`method=get`)
- **Required Permissions**: Authenticated session.
- **Example Syntax**:
  ```text
  er605> interfaces
  er605> interfaces stats
  ```
- **Example Output**:
  ```text
  WAN Mode: 1 active WAN port(s) (Ports: 1)

  === Logical Interfaces (WAN / LAN) ===
  Label  Interface  Proto   Link  IP Address    Netmask        Gateway      MAC Address        DNS            
  -----  ---------  ------  ----  ------------  -------------  -----------  -----------------  ---------------
  WAN1   WAN1       dhcp    Up    203.0.113.15  255.255.255.0  203.0.113.1  AA-BB-CC-00-00-01  1.1.1.1, 8.8.8.8
  LAN    LAN        static  Up    192.168.0.1   255.255.255.0  0.0.0.0      AA-BB-CC-00-00-00  ---            
  ```
- **Verification Status**: Verified against firmware (`interface.lua`, `interface_wan.lua`, `switch.lua`) and unit tests.

---

### `devices`
- **What it does**: Correlates the router's ARP table with active DHCP client leases to display all connected hosts with IP, MAC, hostname, interface, lease time, and discovery source (`DHCP`, `ARP`, `DHCP+ARP`).
- **Router Endpoints**:
  - `/admin/arplist?form=getlist` (`method=get`)
  - `/admin/dhcps?form=client` (`method=get`)
- **Required Permissions**: Authenticated session.
- **Example Syntax**:
  ```text
  er605> devices
  ```
- **Example Output**:
  ```text
  === Connected Devices (ARP: 2, DHCP Leases: 1) ===
  #  IP Address     MAC Address        Hostname        Interface  Lease Time  Source  
  -  -------------  -----------------  --------------  ---------  ----------  --------
  1  192.168.0.50   AA-BB-CC-11-22-33  ---             LAN        ---         ARP     
  2  192.168.0.100  AA-BB-CC-DD-EE-01  workstation-pc  LAN        01:58:20    DHCP+ARP
  ```
- **Verification Status**: Verified against firmware (`arplist.lua`, `dhcps.lua`) and unit tests.

---

### `dhcp leases` / `dhcp reservations` / `dhcp server`
- **What they do**:
  - `dhcp leases`: Lists active DHCP client leases.
  - `dhcp reservations`: Lists static DHCP IP-to-MAC reservations.
  - `dhcp server`: Displays LAN subnet and DHCP pool configurations.
- **Router Endpoints**:
  - `/admin/dhcps?form=client` (`method=get`)
  - `/admin/dhcps?form=reservation` (`method=get`)
  - `/admin/dhcps?form=lan` (`method=get`)
- **Required Permissions**: Authenticated session.
- **Example Syntax**:
  ```text
  er605> dhcp leases
  er605> dhcp reservations
  er605> dhcp server
  ```
- **Verification Status**: Verified against firmware (`dhcps.lua`) and unit tests.

---

### `vlans` / `vlan list` / `vlan show <id>`
- **What they do**: Lists all configured 802.1Q VLANs, untagged/tagged switch port memberships (`Port1(U)`, `Port3(T)`), switch port PVID settings, and single-VLAN details.
- **Router Endpoints**:
  - `/admin/vlansetting?form=vlansettinglist` (`method=get`)
  - `/admin/vlansetting?form=portsettinglist` (`method=get`)
  - `/admin/vlansetting?form=vlanmax` (`method=get`)
- **Required Permissions**: Authenticated session.
- **Example Syntax**:
  ```text
  er605> vlans
  er605> vlan show 20
  ```
- **Example Output**:
  ```text
  === 802.1Q VLAN Configuration ===
  VLAN ID  Name        Member Ports (U=Untagged, T=Tagged)      Used By  Description
  -------  ----------  ---------------------------------------  -------  -----------
  1        VLAN_LAN    Port2(U), Port3(U), Port4(U), Port5(U)   lan      Default LAN
  2        VLAN_WAN1   Port1(U)                                 wan      Default WAN
  20       Guest_VLAN  Port3(T), Port4(U)                       web      Guest      
  ```
- **Verification Status**: Verified against firmware (`vlan_setting.lua`) and unit tests.

---

### `routes`
- **What it does**: Displays the active kernel/system routing table, configured static routes, and policy routing rules.
- **Router Endpoints**:
  - `/admin/routing?form=system_routetbl` (`method=get`)
  - `/admin/routing?form=static_routing` (`method=get`)
  - `/admin/policy_route?form=policy_route` (`method=get`)
- **Required Permissions**: Authenticated session.
- **Example Syntax**:
  ```text
  er605> routes
  ```
- **Verification Status**: Verified against firmware (`routing.lua`, `policy_route.lua`) and unit tests.

---

### `firewall rules`
- **What it does**: Inspects Access Control (ACL) rules, DoS/Flood Attack Defense settings, MAC Filtering rules, IP-MAC Binding / ARP defense lists, and NAT Virtual Server (port forwarding) rules.
- **Router Endpoints**:
  - `/admin/access_ctl?form=acl_inner` (`method=get`)
  - `/admin/dos_defense?form=settings` (`method=get`)
  - `/admin/flood_defense?form=settings` (`method=get`)
  - `/admin/mac_filter?form=mode` & `/admin/mac_filter?form=mac_list` (`method=get`)
  - `/admin/imb?form=enable` & `/admin/imb?form=bind_list` (`method=get`)
  - `/admin/nat?form=vs`, `/admin/nat?form=napt`, `/admin/nat?form=dmz`, `/admin/nat?form=alg` (`method=get`)
- **Required Permissions**: Authenticated session.
- **Example Syntax**:
  ```text
  er605> firewall rules
  ```
- **Verification Status**: Verified against firmware (`access_ctl.lua`, `dos_defense.lua`, `flood_defense.lua`, `mac_filter.lua`, `imb.lua`, `nat.lua`) and unit tests.

---

### `vpn status`
- **What it does**: Inspects IPsec policies and active Security Associations (SAs), OpenVPN servers/clients/tunnels, WireGuard interfaces/peers, L2TP tunnels, and PPTP tunnels (with PSKs and private keys automatically redacted).
- **Router Endpoints**:
  - `/admin/ipsec?form=conn`, `/admin/ipsec?form=ipsec_sa`
  - `/admin/openvpn?form=server_standalone`, `/admin/openvpn?form=client_standalone`, `/admin/openvpn?form=openvpn_tunnel`
  - `/admin/wireguard?form=wireguard`, `/admin/wireguard?form=peers`
  - `/admin/l2tp?form=server`, `/admin/l2tp?form=client`, `/admin/l2tp?form=tunnelinfo`
  - `/admin/pptp_server?form=server_enable`, `/admin/pptp_client?form=client_list`, `/admin/pptp_tunnel?form=pptp_tunnel`
- **Required Permissions**: Authenticated session.
- **Example Syntax**:
  ```text
  er605> vpn status
  ```
- **Verification Status**: Verified against firmware (`ipsec.lua`, `openvpn.lua`, `wireguard.lua`, `l2tp.lua`, `pptp_*.lua`) and unit tests.

---

### `traffic`
- **What it does**: Displays interface RX/TX bytes, packets, and throughput rates (`B/s`, `KB/s`, `MB/s`), per-host IP traffic counters, and switch port packet statistics.
- **Router Endpoints**:
  - `/admin/ifstat?form=list` (`method=get`)
  - `/admin/ipstats?form=setting` & `/admin/ipstats?form=list` (`method=get`)
  - `/admin/switch?form=statistic` (`method=get`)
- **Required Permissions**: Authenticated session.
- **Example Syntax**:
  ```text
  er605> traffic
  ```
- **Verification Status**: Verified against firmware (`ifstat.lua`, `ipstats.lua`, `switch.lua`) and unit tests.

---

### `logs [page] [page_size]`
- **What it does**: Displays paginated system log entries and log severity settings.
- **Router Endpoints**:
  - `/admin/logger?form=loglist` (`method=get`, `params={"page_num":1,"page_size":50}`)
  - `/admin/logger?form=setting` (`method=get`)
- **Required Permissions**: Authenticated session.
- **Example Syntax**:
  ```text
  er605> logs 1 50
  ```
- **Verification Status**: Verified against firmware (`logger.lua`) and unit tests.

---

### `config show [section]`
- **What it does**: Retrieves configuration across `all`, `system`, `network`, `dhcp`, `vlan`, `firewall`, `vpn`, or `services`, recursively redacting all sensitive fields (`password`, `psk`, `private_key`, `secret`, etc.).
- **Router Endpoints**: Queries the respective read endpoints for the chosen section and passes the output through `redact_secrets()`.
- **Required Permissions**: Authenticated session.
- **Example Syntax**:
  ```text
  er605> config show system
  er605> config show all
  ```
- **Verification Status**: Verified against firmware and unit tests.

---

## 3. Configuration & Control Commands

All configuration commands validate parameters client-side before sending requests, print a warning if the change could disrupt connectivity, and require interactive `[y/N]` confirmation (unless `--yes` is explicitly supplied).

| Command | Endpoint & Method | Description | Verification |
|---|---|---|---|
| `vlan create <id> <name> <ports> [--desc <t>]` | `/admin/vlansetting?form=vlansettinglist` (`method=add`) | Creates an 802.1Q VLAN with tagged (`:t`) and untagged (`:u`) ports `1..5`. | Firmware + Unit Tests |
| `vlan update <id> [--name ...] [--ports ...] [--desc ...]` | `/admin/vlansetting?form=vlansettinglist` (`method=set`) | Modifies a user-created (`users=="web"`) 802.1Q VLAN. | Firmware + Unit Tests |
| `vlan delete <id>` | `/admin/vlansetting?form=vlansettinglist` (`method=delete`) | Deletes a user-created 802.1Q VLAN (blocks deletion of system/LAN/WAN VLANs). | Firmware + Unit Tests |
| `dhcp reservation add <ip> <mac> [--interface LAN] [--note <t>] [--bind on\|off]` | `/admin/dhcps?form=reservation` (`method=add`) | Creates a static DHCP IP reservation. | Firmware + Unit Tests |
| `dhcp reservation update <ip> [...]` | `/admin/dhcps?form=reservation` (`method=set`) | Updates an existing static DHCP IP reservation. | Firmware + Unit Tests |
| `dhcp reservation delete <ip>` | `/admin/dhcps?form=reservation` (`method=delete`) | Removes a static DHCP IP reservation. | Firmware + Unit Tests |
| `firewall acl add <name> <ACCEPT\|DROP> [--zone LAN] [--service ALL] [--src ...] [--dest ...]` | `/admin/access_ctl?form=acl_inner` (`method=add`) | Creates an Access Control firewall rule. | Firmware + Unit Tests |
| `firewall acl delete <name_or_key>` | `/admin/access_ctl?form=acl_inner` (`method=delete`) | Deletes a user-created ACL firewall rule. | Firmware + Unit Tests |
| `device block <name> <mac>` | `/admin/mac_filter?form=mac_list` (`method=add`) | Adds a MAC address to the router's MAC filter list. | Firmware + Unit Tests |
| `device unblock <name_or_mac>` | `/admin/mac_filter?form=mac_list` (`method=delete`) | Removes an entry from the MAC filter list by name, MAC, or key. | Firmware + Unit Tests |
| `route add <name> <target> <mask> <gw> [--interface WAN1] [--metric 0]` | `/admin/routing?form=static_routing` (`method=add`) | Adds a static IPv4 route. | Firmware + Unit Tests |
| `route delete <name_or_key>` | `/admin/routing?form=static_routing` (`method=delete`) | Deletes a static IPv4 route. | Firmware + Unit Tests |
| `interface connect <wan_id>` / `interface disconnect <wan_id>` | `/admin/interface_wan?form=connect\|disconnect` (`method=set`) | Connects or disconnects WAN1..WAN4. | Firmware + Unit Tests |
| `config backup <output_path>` | `/admin/firmware?form=config` (`operation=backup`) | Downloads the router's encrypted `.bin` configuration backup file. | Firmware + Unit Tests |
| `logs clear` | `/admin/logger?form=loglist` (`method=delete`) | Clears all system log entries. | Firmware + Unit Tests |
