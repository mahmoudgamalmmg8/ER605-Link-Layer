#!/usr/bin/env python3
"""Local HTTP server for the ER605 CLI Line-by-Line Documentation Web App.

Automatically regenerates `docs/webapp/index.html` and `docs/code-line-by-line-reference.md`
from the current codebase (without modifying any CLI source files) and serves the
interactive portal at http://127.0.0.1:8088.
"""

import argparse
import functools
import http.server
import os
import webbrowser

import build_docs

DOCS_DIR = os.path.dirname(os.path.abspath(__file__))
WEBAPP_DIR = os.path.join(DOCS_DIR, "webapp")


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the ER605 CLI interactive documentation web app.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", "-p", type=int, default=8088, help="Port number (default: 8088)")
    parser.add_argument("--open", action="store_true", help="Automatically open in default web browser")
    args = parser.parse_args()

    # Ensure documentation artifacts are fresh
    build_docs.main()

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=WEBAPP_DIR)
    with http.server.ThreadingHTTPServer((args.host, args.port), handler) as httpd:
        url = f"http://{args.host}:{args.port}/"
        print(f"\n[+] ER605 CLI Documentation Web App running at: {url}")
        print("    Press Ctrl+C to stop.\n")
        if args.open:
            webbrowser.open(url)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Stopped documentation server.")


if __name__ == "__main__":
    main()
