#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 TurboVAS contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify required Greenbone feed objects are available over GMP."""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


FULL_AND_FAST_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
IANA_TCP_UDP_PORT_LIST_ID = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"


def result(status: str, summary: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "summary": summary, "details": details}


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def response_root(response: Any) -> Any | None:
    if isinstance(response, bytes):
        response = response.decode("utf-8", errors="replace")
    if isinstance(response, str):
        try:
            return ET.fromstring(response)
        except ET.ParseError:
            return None
    return response


def object_rows(response: Any, object_tag: str) -> list[dict[str, str | None]]:
    root = response_root(response)
    if root is None or not hasattr(root, "iter"):
        return []
    rows: list[dict[str, str | None]] = []
    for element in root.iter():
        if local_name(str(element.tag)) != object_tag:
            continue
        name_element = None
        try:
            name_element = element.find("name")
        except SyntaxError:
            name_element = None
        rows.append({"id": element.get("id"), "name": getattr(name_element, "text", None) if name_element is not None else None})
    return rows


def expected_present(rows: list[dict[str, str | None]], expected_id: str) -> bool:
    return any(row.get("id") == expected_id for row in rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify TurboVAS runtime feed objects over GMP")
    parser.add_argument("--socket", required=True, help="gvmd Unix socket path")
    parser.add_argument("--username", required=True, help="GMP username")
    parser.add_argument("--password-file", required=True, help="file containing the GMP password")
    parser.add_argument("--timeout", type=int, default=30, help="socket timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    socket_path = Path(args.socket)
    password_path = Path(args.password_file)

    if not socket_path.is_socket():
        print(json.dumps(result("fail", "gvmd socket is not ready", socket=str(socket_path))))
        return 1
    if not password_path.is_file():
        print(json.dumps(result("fail", "password file is missing", password_file=str(password_path))))
        return 1

    password = password_path.read_text(encoding="utf-8").strip()
    if not password:
        print(json.dumps(result("fail", "password file is empty", password_file=str(password_path))))
        return 1

    try:
        from gvm.connections import UnixSocketConnection
        from gvm.protocols.latest import GMP

        connection = UnixSocketConnection(path=socket_path, timeout=args.timeout)
        with GMP(connection=connection) as gmp:
            gmp.authenticate(args.username, password)
            scan_configs = object_rows(gmp.get_scan_configs(), "config")
            port_lists = object_rows(gmp.get_port_lists(), "port_list")
    except Exception as error:  # pylint: disable=broad-except
        print(
            json.dumps(
                result(
                    "fail",
                    "GMP feed object verification failed",
                    error_type=type(error).__name__,
                    error=str(error).replace(password, "[redacted]"),
                )
            )
        )
        return 1

    scan_config_present = expected_present(scan_configs, FULL_AND_FAST_SCAN_CONFIG_ID)
    port_list_present = expected_present(port_lists, IANA_TCP_UDP_PORT_LIST_ID)
    status = "pass" if scan_config_present and port_list_present else "fail"
    print(
        json.dumps(
            result(
                status,
                "Required feed objects are available" if status == "pass" else "Required feed objects are missing",
                scan_configs={"count": len(scan_configs), "expected_id": FULL_AND_FAST_SCAN_CONFIG_ID, "present": scan_config_present},
                port_lists={"count": len(port_lists), "expected_id": IANA_TCP_UDP_PORT_LIST_ID, "present": port_list_present},
            )
        )
    )
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
