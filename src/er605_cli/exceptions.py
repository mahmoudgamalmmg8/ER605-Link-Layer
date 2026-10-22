"""Custom exceptions and firmware error code mappings for ER605 CLI."""

from typing import Any, Dict, Optional

# Extracted from www/webpages/js/chunk-common.962f8363.js (ERROR_CODE)
ERROR_CODES: Dict[int, str] = {
    0: "Success.",
    404: "Operation failed.",
    700: "Failed to log in.",
    701: "Incorrect username.",
    702: "Incorrect password.",
    703: "Session timed out.",
    704: "Session timed out. Please log in again.",
    705: "No change.",
    706: "New port has been set.",
    707: "The old username or password is incorrect.",
    708: "An error occurred setting the new username and password.",
    709: "Number of unsuccessful login attempts has exceeded the upper limit.",
    710: "User conflict (another administrator session is active and preemption is off).",
    800: "The number of time slices has reached the upper limit of 12.",
    801: "The starting time slice should not be greater than the ending time slice.",
    802: "The time slice cannot be null.",
    803: "The week cannot be null.",
    804: "The time slices cannot overlap with each other.",
    1000: "The table is full. No further entries can be added.",
    1001: "The entry already exists.",
    1002: "This entry does not exist.",
    1003: "Failed to add the rule.",
    1004: "Failed to update the rule.",
    1005: "Failed to delete the rule.",
    1006: "Failed to retrieve the rule.",
    1007: "Configuration set failed.",
    1008: "Specified items to be deleted exceed the limit.",
    1010: "UCI commit failed.",
    1012: "Command execution failed.",
    1014: "Illegal operation / no such callback.",
    1020: "The number of entries has exceeded the upper limit.",
    1030: "This entry has been referenced and cannot be deleted.",
    1031: "This entry has been referenced and cannot be modified.",
    1032: "Added reference counts are incorrect.",
    1033: "Deleted reference counts are incorrect.",
    2000: "Configuration failed: system memory utilization is too high (>90%).",
    2001: "Configuration failed: system flash utilization is too high (>95%).",
    15001: "Invalid switch parameters.",
    15101: "Incorrect DHCP parameters.",
    15102: "The starting IP address is required.",
    15103: "Invalid Starting IP address or Ending IP address.",
    15104: "Invalid MAC or IP address.",
    15105: "This entry conflicts with another entry in the ARP/IP-MAC list.",
    15106: "The number of DHCP entries has exceeded the upper limit.",
    15107: "Invalid IP pool.",
    15108: "The DHCP pool conflicts with the VPN IP pool.",
    15111: "The selected IP address has taken effect in DHCP static IP reservation list.",
    33001: "Port conflict in Virtual Server / NAT.",
    33002: "DMZ interface conflict.",
    33003: "One-to-One NAT IP conflict.",
    34001: "Invalid routing parameters.",
    34002: "Routing entries reached maximum limit.",
    34003: "Duplicate routing entry.",
    34004: "Duplicate routing rule name.",
    35001: "Invalid firewall table item.",
    36001: "IP-MAC binding description too long.",
    36002: "IP-MAC binding IP conflicts with LAN IP.",
    49000: "Failed to export IP-MAC entry.",
    49001: "The number of IP-MAC entries has exceeded the limit.",
    53100: "Configuration import failed.",
    53101: "Upgrade failed.",
    53102: "Incorrect file. Configuration import failed.",
    53103: "Model does not match. Configuration import failed.",
    80001: "The VLAN ID already exists.",
    80003: "Failed to add the VLAN entry.",
    80004: "The VLAN entry does not exist.",
    80005: "The first/system VLAN cannot be deleted.",
    80006: "Failed to modify the VLAN entry.",
    80007: "The current VLAN has been referenced and cannot be deleted.",
    80008: "Current VLAN entries have exceeded the maximum number allowed.",
    80010: "Failed to initialize the port list.",
    80011: "The link type and PVID of each port cannot be modified at the same time.",
    80012: "Invalid PVID.",
    80013: "Port list setting failed.",
}


def format_error_code(error_code: Any) -> str:
    """Return a human-readable description for a router error_code."""
    try:
        code_int = int(str(error_code).strip())
    except (ValueError, TypeError):
        return f"Router error code: {error_code}"
    desc = ERROR_CODES.get(code_int, "Unknown router error.")
    return f"[Error {code_int}] {desc}"


class ER605Error(Exception):
    """Base exception for all ER605 CLI errors."""

    def __init__(
        self,
        message: str,
        error_code: Optional[Any] = None,
        others: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.error_code = str(error_code) if error_code is not None else None
        self.others = others or {}
        self.data = data


class TransportError(ER605Error):
    """Raised on network timeouts, unreachable host, TLS error, or HTTP failure."""


class MalformedResponseError(ER605Error):
    """Raised when the router returns non-JSON or unexpected payload structure."""


class AuthenticationError(ER605Error):
    """Raised when login fails, credentials are invalid, or user conflict occurs."""


class SessionExpiredError(AuthenticationError):
    """Raised when error_code 703/704 or unauthenticated redirect is encountered."""


class PermissionDeniedError(ER605Error):
    """Raised when CSRF/Referer validation fails or operation is forbidden."""


class OperationError(ER605Error):
    """Raised when a router RPC returns a non-zero error_code."""


class ValidationError(ER605Error):
    """Raised when user command arguments fail local validation before sending."""


class UnsupportedFeatureError(ER605Error):
    """Raised when a requested feature is not supported by the ER605 v1 firmware."""
