# SPDX-FileCopyrightText: 2026 TurboVAS contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


DEFAULT_FILTER = "first=1 rows=25 sort-reverse=created"


def parse_args(args: Namespace) -> Namespace:
    parser = ArgumentParser(
        prefix_chars="+",
        add_help=False,
        formatter_class=RawTextHelpFormatter,
        description="List TurboVAS scope reports.",
    )
    parser.add_argument(
        "+h",
        "++help",
        action="help",
        help="Show this help message and exit.",
    )
    parser.add_argument(
        "++filter",
        default=DEFAULT_FILTER,
        help=f"Scope report filter string. Default: {DEFAULT_FILTER}",
    )
    script_args = args.script[1:] if args.script else []
    parsed_args, _ = parser.parse_known_args(script_args)
    return parsed_args


def main(gmp: Gmp, args: Namespace) -> None:
    parsed_args = parse_args(args)
    response_xml = gmp.get_scope_reports(
        details=True,
        filter_string=parsed_args.filter,
    )
    reports_xml = response_xml.xpath("scope_report")

    heading = [
        "#",
        "Name",
        "Id",
        "Scope",
        "Created",
        "Latest Evidence",
        "Source Reports",
        "Hosts With Evidence",
        "Vulnerabilities",
    ]
    rows = []

    print("Listing scope reports.\n")

    for number, report in enumerate(reports_xml, start=1):
        counts = report.find("counts")
        rows.append(
            [
                str(number),
                "".join(report.xpath("name/text()")),
                report.get("id"),
                "".join(report.xpath("scope/name/text()")),
                "".join(report.xpath("created/text()")),
                "".join(report.xpath("latest_evidence_time/text()")),
                "" if counts is None else "".join(counts.xpath("source_reports/text()")),
                "" if counts is None else "".join(counts.xpath("hosts_with_evidence/text()")),
                "" if counts is None else "".join(counts.xpath("vulnerabilities_total/text()")),
            ]
        )

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
