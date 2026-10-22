# TP-Link ER605 (UN) v1.0 Firmware Analysis (`1.3.2 Build 20251030 Rel.16640`)

## 1. Extracted Firmware Root
The analysis was conducted directly against the extracted SquashFS root filesystem located at:
- `ER605v1_un_1.3.2_20251030-rel16640_up_2025-10-29_20.40.05.bin.extracted/0x1a9de4-squashfs/`

*(Note: No pre-existing `er605_monitor_report.json` was present in the workspace; all endpoints and data structures were verified directly from the firmware's Lua controllers, frontend JavaScript/HTML files, and live router responses on `192.168.0.1`.)*

---

## 2. Evaluation of Management Interfaces

| Interface | Firmware Location | Default State | Findings |
|---|---|---|---|
| **HTTP / HTTPS Web RPC (`uhttpd` + LuCI)** | `/etc/config/uhttpd`, `/www/cgi-bin/luci`, `/usr/lib/lua/luci/` | **Enabled** (TCP 80 & 443) | Primary management interface used by the official web administration UI in standalone mode. |
| **SSH (`dropbear`)** | `/etc/config/dropbear`, `/etc/init.d/dropbear` | **Disabled** (`ssh_port_switch 'off'`) | Even when enabled via remote assistance, `/etc/init.d/dropbear` dynamically overwrites the `root` password using an internal hash derived from the device MAC address and admin username rather than the web admin password. Not usable as a standard CLI interface. |
| **Telnet (`busybox telnetd`)** | `/etc/init.d/telnet` | **Disabled** (`#START=50` commented out) | Service is disabled in init scripts and has no web toggle. |
| **SNMP (`snmpd`)** | `/etc/config/snmpd`, `/usr/lib/lua/luci/controller/admin/snmp.lua` | **Disabled** (`snmp_enable 'off'`) | Read-only (`access ... write none`) when enabled by the user. |

---

## 3. Web Administration Architecture & Transport Protocol

### 3.1 URL Structure (`usr/lib/lua/luci/dispatcher.lua`, `www/webpages/js/su/data/proxy.js`)
All management operations are dispatched through `/www/cgi-bin/luci`:
- **Pre-login endpoints**: `POST /cgi-bin/luci/;stok=/<module>?form=<form>`
- **Authenticated endpoints**: `POST /cgi-bin/luci/;stok=<32_hex_token>/admin/<module>?form=<form>`

### 3.2 Request Encoding
Requests use `Content-Type: application/x-www-form-urlencoded; charset=UTF-8`.
- Standard proxy calls (`$.su.Proxy`) encode a JSON object inside the `data` form parameter:
  ```text
  data={"method":"get","params":{}}
  ```
- Supported methods across controllers (`luci.controller.admin.*`):
  - `get` (`$.su.Proxy.read`)
  - `set` (`$.su.Proxy.write` / form submit / grid update)
  - `add` (grid insert)
  - `delete` (grid remove)
- Certain specialized endpoints (`/locale?form=lang` and `/admin/firmware?form=config`) use direct form parameters (`operation=read` or `operation=backup`).

### 3.3 CSRF / Referer Enforcement (`usr/lib/lua/luci/dispatcher.lua`)
Before executing a controller target, `dispatcher.lua` calls `checktypes.check_safe_request(http.getenv("HTTP_REFERER"))`.
- If the `Referer` HTTP header is missing or does not match the router's host/scheme (`http://<router_ip>/webpages/...`), the router returns HTTP 200 with body `<h1>Not Found</h1>`.
- `ER605Client` automatically attaches `Referer: <base_url>/webpages/index.html` (or `login.html` prior to login) and `X-Requested-With: XMLHttpRequest` on every request.

---

## 4. Authentication & Session Lifecycle

### 4.1 Pre-Login Discovery
1. `POST /cgi-bin/luci/;stok=/locale?form=lang` (`operation=read`)
   - Live response from `192.168.0.1`:
     ```json
     {"id":1,"result":{"locale":"en_US","radio":0,"model":"ER605 v1.0","force":false,"multiwan":1},"error_code":"0"}
     ```
2. `POST /cgi-bin/luci/;stok=/userconfig?form=cfg_save` (`data={"method":"get"}`)
   - Live response from `192.168.0.1`:
     ```json
     {"id":1,"result":{"https_port":"443","redirect_https":"on","status":"Saved","dft_pwd_status":"Modify","qs_flag":"0","config_status":"Modify"},"error_code":"0"}
     ```

### 4.2 RSA Password Encryption (`www/webpages/js/libs/encrypt.js` & `www/webpages/login.html`)
1. Query `POST /cgi-bin/luci/;stok=/login?form=login` with `data={"method":"get"}`.
   - Returns `result.password = [modulus_hex, exponent_hex]` (1024-bit RSA public key, `e = "010001"`).
2. `$.su.encrypt` splits the UTF-8 plaintext password into chunks of the modulus byte length (128 bytes), right-pads each chunk with zero bytes (`0x00`), interprets the bytes as a big-endian integer $m$, and computes $c = m^e \bmod n$ formatted as a zero-padded lowercase hexadecimal string (256 hex characters per block).
3. Submit `POST /cgi-bin/luci/;stok=/login?form=login` with:
   ```json
   {"method":"login","params":{"username":"<user>","password":"<256_char_hex_ciphertext>"}}
   ```
4. On success (`error_code == "0"`):
   - The response returns `result.stok` (32-character hex token).
   - The HTTP response sets `Set-Cookie: sysauth=<cookie_value>; path=/; HttpOnly`.
   - Both the URL `stok` token and the `sysauth` cookie are required for subsequent `/admin/*` requests.
5. On session timeout or preemption by another login, the router returns `error_code: "703"` (`ERR_HTTP_ERR_CGI_INVALID_ANSI`) or `"704"` (`ERR_HTTP_ERR_CGI_SESSION_TIMEOUT`).
6. Logout is performed via `POST /cgi-bin/luci/;stok=<stok>/admin/system?form=logout` (`data={"method":"get"}`).
