"""HTTP/HTTPS transport and JSON-over-form RPC client for TP-Link ER605.

Implements the exact protocol used by `www/webpages/js/su/data/proxy.js` and
`usr/lib/lua/luci/dispatcher.lua`:
- Endpoint URL: `/cgi-bin/luci/;stok=<stok>/<module>?form=<form_name>`
- Form-encoded POST body: `data={"method":"get|set|add|delete","params":{...}}`
  (or direct form fields such as `operation=read` for `/locale?form=lang`)
- CSRF protection: `Referer: <base_url>/webpages/...` required by `check_safe_request`
- Session state: `stok` URL token + `sysauth` HTTP cookie
- TLS verification: enabled by default when HTTPS is used (`ssl.create_default_context()`).
"""

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Optional, Tuple

from .auth import extract_rsa_key_pair, rsa_encrypt_nopadding
from .exceptions import (
    AuthenticationError,
    MalformedResponseError,
    OperationError,
    PermissionDeniedError,
    SessionExpiredError,
    TransportError,
    format_error_code,
)
from .session import RouterSession


class ER605Client:
    """Low-level RPC and session client for the TP-Link ER605 router."""

    def __init__(
        self,
        host: str = "192.168.0.1",
        scheme: str = "http",
        port: Optional[int] = None,
        verify_tls: bool = True,
        ca_file: Optional[str] = None,
        timeout: float = 15.0,
        reauth_callback: Optional[Callable[[], Tuple[str, str]]] = None,
    ) -> None:
        self.session = RouterSession(
            host=host,
            scheme=scheme.lower(),
            port=port,
            verify_tls=verify_tls,
            ca_file=ca_file,
            timeout=timeout,
        )
        self.reauth_callback = reauth_callback
        self._opener = self._build_opener()

    def _build_opener(self) -> urllib.request.OpenerDirector:
        handlers = [urllib.request.HTTPCookieProcessor(self.session.cookie_jar)]
        if self.session.scheme == "https":
            if self.session.verify_tls:
                ctx = ssl.create_default_context(cafile=self.session.ca_file)
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        return urllib.request.build_opener(*handlers)

    def configure_target(
        self,
        host: str,
        scheme: Optional[str] = None,
        port: Optional[int] = None,
        verify_tls: Optional[bool] = None,
        ca_file: Optional[str] = None,
    ) -> None:
        """Reconfigure router connection target and reset session state."""
        self.session.clear()
        self.session.host = host
        if scheme is not None:
            self.session.scheme = scheme.lower()
        self.session.port = port
        if verify_tls is not None:
            self.session.verify_tls = verify_tls
        if ca_file is not None:
            self.session.ca_file = ca_file
        self._opener = self._build_opener()

    def _post_raw(
        self,
        endpoint: str,
        form_fields: Dict[str, str],
        timeout: Optional[float] = None,
    ) -> Tuple[bytes, Dict[str, str]]:
        """Send an HTTP POST request with Referer and X-Requested-With headers."""
        url = self.session.build_endpoint_url(endpoint)
        encoded = urllib.parse.urlencode(form_fields).encode("utf-8")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": self.session.referer_url,
            "Origin": self.session.base_url,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "User-Agent": "er605-cli/1.0",
        }
        req = urllib.request.Request(url, data=encoded, headers=headers, method="POST")
        req_timeout = timeout if timeout is not None else self.session.timeout
        try:
            with self._opener.open(req, timeout=req_timeout) as resp:
                body = resp.read()
                resp_headers = {k.lower(): v for k, v in resp.info().items()}
                return body, resp_headers
        except urllib.error.HTTPError as exc:
            err_body = b""
            try:
                err_body = exc.read()
            except Exception:
                pass
            if exc.code == 403:
                raise PermissionDeniedError(
                    f"HTTP 403 Forbidden on {endpoint}."
                ) from exc
            if exc.code == 404 or b"<h1>Not Found</h1>" in err_body:
                raise PermissionDeniedError(
                    f"Endpoint {endpoint} returned Not Found (CSRF Referer check failed or invalid endpoint)."
                ) from exc
            raise TransportError(f"HTTP {exc.code} error on {endpoint}: {exc.reason}") from exc
        except ssl.SSLError as exc:
            raise TransportError(
                f"TLS certificate verification failed ({exc}). "
                "The ER605 uses a self-signed certificate by default; use HTTP on a trusted LAN, "
                "provide --ca-cert, or pass --insecure to explicitly skip TLS verification."
            ) from exc
        except urllib.error.URLError as exc:
            raise TransportError(
                f"Network error connecting to {self.session.base_url}: {exc.reason}"
            ) from exc
        except TimeoutError as exc:
            raise TransportError(
                f"Request to {self.session.base_url}{endpoint} timed out after {req_timeout}s."
            ) from exc

    def _parse_json_response(self, raw_bytes: bytes, endpoint: str) -> Dict[str, Any]:
        """Decode and validate a LuCI JSON response envelope."""
        text = raw_bytes.decode("utf-8", errors="replace").strip()
        if not text:
            raise MalformedResponseError(f"Empty response from {endpoint}.")
        if text == "<h1>Not Found</h1>":
            raise PermissionDeniedError(
                f"Router rejected request to {endpoint} with '<h1>Not Found</h1>' "
                "(missing/invalid Referer or unknown LuCI route)."
            )
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise MalformedResponseError(
                f"Non-JSON response from {endpoint}: {text[:160]}"
            ) from exc
        if not isinstance(payload, dict):
            raise MalformedResponseError(
                f"Expected JSON object from {endpoint}, got {type(payload).__name__}."
            )
        return payload

    def request_Full(
        self,
        endpoint: str,
        method: str = "get",
        params: Optional[Dict[str, Any]] = None,
        extra_top_fields: Optional[Dict[str, Any]] = None,
        raw_form: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        allow_reauth: bool = True,
    ) -> Dict[str, Any]:
        """Execute a LuCI RPC request and return the full parsed JSON dict (`result`, `others`, `error_code`)."""
        if raw_form is not None:
            form_fields = raw_form
        else:
            rpc_data: Dict[str, Any] = {"method": method}
            if params is not None:
                rpc_data["params"] = params
            if extra_top_fields:
                rpc_data.update(extra_top_fields)
            form_fields = {"data": json.dumps(rpc_data, separators=(",", ":"))}

        raw_bytes, _ = self._post_raw(endpoint, form_fields, timeout=timeout)
        payload = self._parse_json_response(raw_bytes, endpoint)

        err_code = str(payload.get("error_code", "0")).strip()
        if err_code in ("0", "ERR_OK"):
            return payload

        if err_code == "permission denied":
            raise PermissionDeniedError(
                f"Permission denied on {endpoint} (session missing or invalid)."
            )

        if err_code in ("703", "704", "ERR_COM_LOGIN_TIMEOUT"):
            self.session.clear()
            if allow_reauth and self.reauth_callback is not None:
                username, password = self.reauth_callback()
                self.login(username, password)
                return self.request_Full(
                    endpoint=endpoint,
                    method=method,
                    params=params,
                    extra_top_fields=extra_top_fields,
                    raw_form=raw_form,
                    timeout=timeout,
                    allow_reauth=False,
                )
            raise SessionExpiredError(
                format_error_code(err_code),
                error_code=err_code,
                others=payload.get("others"),
                data=payload.get("result"),
            )

        raise OperationError(
            format_error_code(err_code),
            error_code=err_code,
            others=payload.get("others"),
            data=payload.get("result"),
        )

    def read(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """Corresponds to `$.su.Proxy.prototype.read` (`method="get"`). Returns `payload["result"]`."""
        payload = self.request_Full(endpoint, method="get", params=params, timeout=timeout)
        return payload.get("result")

    def write(
        self,
        endpoint: str,
        method: str = "set",
        params: Optional[Dict[str, Any]] = None,
        extra_top_fields: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """Corresponds to `$.su.Proxy.prototype.write` (`method="set|add|delete"`). Returns `payload["result"]`."""
        payload = self.request_Full(
            endpoint,
            method=method,
            params=params,
            extra_top_fields=extra_top_fields,
            timeout=timeout,
        )
        return payload.get("result")

    def probe_prelogin_info(self) -> Dict[str, Any]:
        """Query pre-login endpoints (`/locale?form=lang` and `/userconfig?form=cfg_save`).

        Does not require authentication (`stok=""`). Used to verify connectivity,
        detect model version, and check whether factory defaults or HTTPS redirect are active.
        """
        locale_resp = self.request_Full(
            "/locale?form=lang",
            raw_form={"operation": "read"},
            allow_reauth=False,
        )
        cfg_resp = self.request_Full(
            "/userconfig?form=cfg_save",
            method="get",
            allow_reauth=False,
        )
        locale_res = locale_resp.get("result") or {}
        cfg_res = cfg_resp.get("result") or {}
        if isinstance(locale_res, dict) and locale_res.get("model"):
            self.session.model = str(locale_res["model"])
        if isinstance(cfg_res, dict):
            self.session.redirect_https = cfg_res.get("redirect_https")
            try:
                self.session.https_port = int(cfg_res.get("https_port", 443))
            except (ValueError, TypeError):
                self.session.https_port = 443
        return {
            "locale": locale_res,
            "config_state": cfg_res,
        }

    def fetch_rsa_keys(self) -> Tuple[str, str]:
        """Fetch the RSA public key `[modulus_hex, exponent_hex]` from `/login?form=login`."""
        res = self.read("/login?form=login")
        n_hex, e_hex = extract_rsa_key_pair(res)
        return n_hex, e_hex

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate to the ER605 router using its RSA login flow.

        Steps verified against `www/webpages/login.html` and `usr/lib/lua/luci/controller/login.lua`:
        1. Clear any stale session state.
        2. Query `/login?form=login` (`method="get"`) to get RSA public key `[n, e]`.
        3. Encrypt `password` using `rsa_encrypt_nopadding(password, n, e)`.
        4. Submit `{"method":"login","params":{"username":username,"password":encrypted_password}}`
           to `/login?form=login`.
        5. Store the returned `stok` token and verify that `sysauth` cookie was set.
        """
        if not username:
            raise AuthenticationError("Username cannot be empty.")
        if not password:
            raise AuthenticationError("Password cannot be empty.")

        self.session.clear()
        try:
            self.probe_prelogin_info()
        except ER605Error:
            # Non-fatal if prelogin info fails, proceed to key fetch
            pass

        n_hex, e_hex = self.fetch_rsa_keys()
        encrypted_password = rsa_encrypt_nopadding(password, n_hex, e_hex)

        try:
            payload = self.request_Full(
                "/login?form=login",
                method="login",
                params={
                    "username": username,
                    "password": encrypted_password,
                },
                allow_reauth=False,
            )
        except OperationError as exc:
            code = exc.error_code
            data = exc.data if isinstance(exc.data, dict) else {}
            if code == "700":
                fail_cnt = data.get("failureCount")
                allowed = data.get("attemptsAllowed")
                detail = ""
                if fail_cnt is not None and allowed is not None:
                    detail = f" (Failed attempts: {fail_cnt}, Remaining allowed: {allowed})"
                raise AuthenticationError(
                    f"Login failed: invalid username or password.{detail}",
                    error_code=code,
                    data=data,
                ) from exc
            if code == "709":
                raise AuthenticationError(
                    "Maximum login attempts exceeded. Account is temporarily locked.",
                    error_code=code,
                    data=data,
                ) from exc
            if code == "710":
                user = data.get("logined_user", "unknown")
                ip = data.get("logined_ip", "unknown")
                raise AuthenticationError(
                    f"Login conflict: user '{user}' is already logged in from {ip} and session preemption is disabled.",
                    error_code=code,
                    data=data,
                ) from exc
            raise AuthenticationError(
                f"Login failed: {exc}",
                error_code=code,
                data=data,
            ) from exc

        result = payload.get("result") or {}
        stok = result.get("stok") if isinstance(result, dict) else None
        if not stok:
            raise AuthenticationError("Login response did not contain a valid session token.")

        self.session.set_stok(str(stok))
        self.session.username = username

        if not self.session.is_authenticated:
            self.session.clear()
            raise AuthenticationError(
                "Login succeeded but no 'sysauth' session cookie was received from the router."
            )

        return {
            "authenticated": True,
            "host": self.session.host,
            "scheme": self.session.scheme,
            "model": self.session.model,
            "username": username,
        }

    def logout(self) -> Dict[str, Any]:
        """Log out of the current session via `/admin/system?form=logout` and clear credentials."""
        if not self.session.is_authenticated:
            self.session.clear()
            return {"logged_out": True, "note": "No active session."}
        try:
            self.write("/admin/system?form=logout", method="set", params={})
        except ER605Error:
            # Even if the server session already timed out, clear local session cleanly
            pass
        finally:
            self.session.clear()
        return {"logged_out": True}

    def download_binary(
        self,
        endpoint: str,
        form_fields: Dict[str, str],
        timeout: Optional[float] = 60.0,
    ) -> Tuple[bytes, Optional[str]]:
        """Download binary attachment (such as config backup) from a LuCI form endpoint."""
        raw_bytes, headers = self._post_raw(endpoint, form_fields, timeout=timeout)
        disp = headers.get("content-disposition", "")
        filename = None
        if "filename=" in disp:
            part = disp.split("filename=", 1)[1].strip()
            filename = part.strip("\"'")
        # Check if router returned a JSON error instead of binary file
        if raw_bytes.startswith(b"{") and b"error_code" in raw_bytes[:200]:
            payload = self._parse_json_response(raw_bytes, endpoint)
            err_code = str(payload.get("error_code", "0")).strip()
            if err_code not in ("0", "ERR_OK"):
                raise OperationError(
                    format_error_code(err_code),
                    error_code=err_code,
                    others=payload.get("others"),
                    data=payload.get("result"),
                )
        return raw_bytes, filename
