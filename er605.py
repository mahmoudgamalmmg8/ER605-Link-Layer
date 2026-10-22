#!/usr/bin/env python3
"""ER605 CLI — Standalone Firmware-Based Manual Administration & Inspection Tool."""

import getpass
import os
import sys
from typing import List, Optional

# Add src/ directory to sys.path so er605.py runs directly without installation
_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.join(_REPO_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from er605_cli.client import ER605Client
from er605_cli.commands import CommandDispatcher, ER605Shell
from er605_cli.exceptions import ER605Error
from er605_cli.parser import build_cli_arg_parser


def _prompt_password_stderr(prompt: str = "Password: ") -> str:
    """Prompt for password via /dev/tty or stderr so stdout remains clean for --json."""
    return getpass.getpass(prompt=prompt, stream=sys.stderr)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_cli_arg_parser()
    args = parser.parse_args(argv)

    client = ER605Client(
        host=args.host,
        scheme=args.scheme,
        port=args.port,
        verify_tls=not args.insecure,
        ca_file=args.ca_cert,
        timeout=args.timeout,
    )

    dispatcher = CommandDispatcher(
        client=client,
        default_json=args.json,
        auto_confirm=args.yes,
        password_fn=_prompt_password_stderr,
    )

    # Non-interactive single command execution
    if args.command:
        cmd_tokens = list(args.command)
        if cmd_tokens and cmd_tokens[0] == "--":
            cmd_tokens = cmd_tokens[1:]
        if not cmd_tokens:
            parser.print_help()
            return 0

        first_word = cmd_tokens[0].lower()
        needs_auth = first_word not in (
            "help",
            "?",
            "probe",
            "connect",
            "ssh",
            "telnet",
            "wifi",
            "wireless",
            "wlan",
            "reset",
            "factory-reset",
            "reboot",
        )

        try:
            if needs_auth and first_word != "login":
                username = args.username
                if not username:
                    sys.stderr.write("Username [admin]: ")
                    sys.stderr.flush()
                    user_in = sys.stdin.readline().strip()
                    username = user_in or "admin"
                password = _prompt_password_stderr("Password: ")
                client.login(username, password)

            exit_code = dispatcher.dispatch_tokens(cmd_tokens)
            return exit_code
        except ER605Error as exc:
            if args.json:
                from er605_cli.output import format_json

                print(
                    format_json(
                        {
                            "error": True,
                            "type": type(exc).__name__,
                            "message": str(exc),
                        }
                    )
                )
            else:
                print(f"[-] {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            print("\n[-] Interrupted.", file=sys.stderr)
            return 130
        finally:
            if client.session.is_authenticated:
                try:
                    client.logout()
                except ER605Error:
                    pass

    # Interactive mode
    print("ER605 CLI")
    model_str = ""
    try:
        info = client.probe_prelogin_info()
        detected = info.get("locale", {}).get("model")
        if detected:
            model_str = f" ({detected})"
    except ER605Error as exc:
        print(f"[!] Note: Pre-login check to {client.session.base_url} reported: {exc}", file=sys.stderr)

    print(f"Router: {args.host}{model_str}\n")

    try:
        username = args.username
        if not username:
            user_in = input("Username [admin]: ").strip()
            username = user_in or "admin"
        password = _prompt_password_stderr("Password: ")
        if password:
            client.login(username, password)
            print("\n[+] Authenticated successfully.\n")
        else:
            print("\n[!] Empty password entered; starting unauthenticated shell. Type 'login' to authenticate.\n")
    except ER605Error as exc:
        print(f"\n[-] Authentication failed: {exc}")
        print("[!] Entering shell in unauthenticated mode. Use 'probe', 'connect <host>', or 'login' when ready.\n")
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Skipped initial login. Type 'login' inside the shell to authenticate.\n")

    shell = ER605Shell(dispatcher)
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("")
        shell.do_exit("")
    return 0


if __name__ == "__main__":
    sys.exit(main())
