"""Session state management for ER605 CLI.

Never logs or prints passwords, stok tokens, or sysauth cookies.
"""

from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from typing import Optional


@dataclass
class RouterSession:
    """Holds authenticated session state for an ER605 router connection."""

    host: str = "192.168.0.1"
    scheme: str = "http"
    port: Optional[int] = None
    verify_tls: bool = True
    ca_file: Optional[str] = None
    timeout: float = 15.0
    username: Optional[str] = None
    _stok: str = field(default="", repr=False)
    cookie_jar: CookieJar = field(default_factory=CookieJar, repr=False)
    model: str = "ER605"
    redirect_https: Optional[str] = None
    https_port: Optional[int] = None

    @property
    def base_url(self) -> str:
        """Return the base URL (`scheme://host[:port]`) without trailing slash."""
        default_port = 443 if self.scheme == "https" else 80
        if self.port and self.port != default_port:
            return f"{self.scheme}://{self.host}:{self.port}"
        return f"{self.scheme}://{self.host}"

    @property
    def referer_url(self) -> str:
        """Return the legitimate web UI Referer required by `check_safe_request`."""
        if self.is_authenticated:
            return f"{self.base_url}/webpages/index.html"
        return f"{self.base_url}/webpages/login.html"

    @property
    def is_authenticated(self) -> bool:
        """Return True if we have both a non-empty stok token and a sysauth cookie."""
        if not self._stok:
            return False
        return any(c.name == "sysauth" and c.value for c in self.cookie_jar)

    @property
    def stok(self) -> str:
        """Return the current stok token (for internal URL construction only)."""
        return self._stok

    def set_stok(self, token: str) -> None:
        """Store the stok token."""
        self._stok = (token or "").strip()

    def clear(self) -> None:
        """Clear session token and cookies on logout or session expiry."""
        self._stok = ""
        self.cookie_jar.clear()

    def build_endpoint_url(self, endpoint: str) -> str:
        """Construct `/cgi-bin/luci/;stok=<stok><endpoint>` matching `$.su.url`."""
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        return f"{self.base_url}/cgi-bin/luci/;stok={self._stok}{endpoint}"
