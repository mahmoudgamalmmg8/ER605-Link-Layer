"""Command-line and interactive command parsing utilities for ER605 CLI."""

import argparse
import shlex
from typing import Dict, List, Optional, Tuple

from .exceptions import ValidationError


def build_cli_arg_parser() -> argparse.ArgumentParser:
    """Create the top-level `argparse.ArgumentParser` for `er605.py`."""
    parser = argparse.ArgumentParser(
        prog="er605-cli",
        description=(
            "TP-Link ER605 v1 Manual Administration & Inspection CLI.\n"
            "Run without a subcommand to enter the interactive shell (er605>),\n"
            "or pass a command directly for non-interactive execution."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 er605.py                              # Interactive shell (default 192.168.0.1)\n"
            "  python3 er605.py --host 192.168.0.1 probe     # Pre-login connectivity & model check\n"
            "  python3 er605.py -u admin status              # Non-interactive status check\n"
            "  python3 er605.py -u admin --json interfaces   # Machine-readable JSON output\n"
            "  python3 er605.py -u admin vlan list           # Inspect configured 802.1Q VLANs\n"
        ),
    )
    parser.add_argument(
        "--host",
        "-H",
        default="192.168.0.1",
        help="Router IP address or hostname (default: 192.168.0.1)",
    )
    parser.add_argument(
        "--scheme",
        choices=["http", "https"],
        default="http",
        help="Transport protocol scheme (default: http)",
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=None,
        help="Custom HTTP/HTTPS port (default: 80 for http, 443 for https)",
    )
    parser.add_argument(
        "--username",
        "-u",
        default=None,
        help="Administrator username for login",
    )
    parser.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        default=False,
        help="Explicitly disable TLS certificate verification when using HTTPS (enabled by default)",
    )
    parser.add_argument(
        "--ca-cert",
        default=None,
        help="Path to trusted CA or router certificate bundle for HTTPS verification",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP request timeout in seconds (default: 15.0)",
    )
    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        default=False,
        help="Emit structured JSON output instead of human-readable tables",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        default=False,
        help="Skip interactive [y/N] confirmation prompts for configuration changes",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Optional command to execute non-interactively (e.g., 'status', 'dhcp leases', 'vlan list')",
    )
    return parser


def tokenize_command_line(line: str) -> List[str]:
    """Split an interactive command line using POSIX shell quoting rules."""
    try:
        return shlex.split(line)
    except ValueError as exc:
        raise ValidationError(f"Command syntax error: {exc}") from exc


def parse_flag_options(
    tokens: List[str],
    allowed_value_flags: Tuple[str, ...] = (),
    allowed_bool_flags: Tuple[str, ...] = ("--json", "-j", "--yes", "-y"),
) -> Tuple[List[str], Dict[str, str], Dict[str, bool]]:
    """Extract `--key value` and boolean flags from a token list.

    Returns `(positional_args, value_flags, bool_flags)`.
    """
    positional: List[str] = []
    val_flags: Dict[str, str] = {}
    bool_flags: Dict[str, bool] = {}

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in allowed_bool_flags:
            bool_flags[tok] = True
            i += 1
        elif tok in allowed_value_flags:
            if i + 1 >= len(tokens):
                raise ValidationError(f"Option '{tok}' requires a value.")
            val_flags[tok] = tokens[i + 1]
            i += 2
        elif tok.startswith("--") and "=" in tok:
            k, v = tok.split("=", 1)
            if k in allowed_value_flags:
                val_flags[k] = v
                i += 1
            else:
                raise ValidationError(f"Unknown option '{k}'.")
        elif tok.startswith("-"):
            raise ValidationError(f"Unknown option '{tok}'.")
        else:
            positional.append(tok)
            i += 1

    return positional, val_flags, bool_flags
