"""live_pcap_forensics_analyzer CLI.

사용 예:
    python -m live_pcap_forensics_analyzer capture.pcap
    python -m live_pcap_forensics_analyzer capture.pcap --ioc iocs.txt --html report.html -v

종료 코드: 0=이상 없음, 1=오류, 2=high/critical 탐지 존재 (배치 자동화용)
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .analyzer import analyze
from .pcapio import PcapFormatError
from . import report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="live-pcap_forensics_analyzer",
        description="PCAP/PCAPNG 네트워크 포렌식 분석기 (표준 라이브러리만 사용)",
    )
    p.add_argument("pcap", help="분석할 .pcap / .pcapng 파일")
    p.add_argument("--ioc", metavar="FILE", help="침해지표 목록 (IP/CIDR/도메인, 줄 단위)")
    p.add_argument("--html", metavar="FILE", help="HTML 리포트 저장 경로")
    p.add_argument("--json", metavar="FILE", help="JSON 결과 저장 경로")
    p.add_argument("--csv", metavar="FILE", help="세션 목록 CSV 저장 경로")
    p.add_argument("-v", "--verbose", action="store_true", help="증거/MITRE/대응까지 출력")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = analyze(args.pcap, ioc_path=args.ioc)
    except FileNotFoundError:
        print(f"오류: 파일을 찾을 수 없습니다 - {args.pcap}", file=sys.stderr)
        return 1
    except PcapFormatError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 1

    print(report.console_summary(result, verbose=args.verbose))
    if args.html:
        report.to_html(result, args.html)
        print(f"HTML 리포트 저장: {args.html}")
    if args.json:
        report.to_json(result, args.json)
        print(f"JSON 저장: {args.json}")
    if args.csv:
        report.to_csv(result, args.csv)
        print(f"CSV 저장: {args.csv}")

    if any(f.severity in ("high", "critical") for f in result.findings):
        return 2
    return 0
