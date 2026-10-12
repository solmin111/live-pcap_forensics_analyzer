"""실시간 탐지 모드.

⚠ 본인이 소유하거나 관리 권한을 위임받은 호스트/네트워크에서만 사용할 것.
   이 모드는 자기 PC를 지나는 트래픽을 모니터링하는 방어·학습용 기능이다.

두 가지 방식을 지원한다.

A. 패킷 모드 (관리자 권한 세션 필요, 설치물 없음)
   Windows raw socket(SIO_RCVALL)로 이 호스트의 IPv4 패킷을 수신해
   파일 분석과 동일한 파이프라인(디코딩→세션→재조립→탐지)을 주기적으로 돌린다.
   받은 패킷은 LINKTYPE_RAW_IP pcap으로 저장해 증거를 남길 수 있다.
   제약: 이더넷/ARP 계층이 없어 ARP 스푸핑 탐지는 불가, 루프백 제외.

B. 플로우 모드 (승격 불필요)
   netstat 연결 테이블과 DNS 클라이언트 캐시를 폴링해 연결 패턴 기반
   탐지(비커닝, 아웃바운드 스캔, IOC 접촉, DGA 의심 캐시)만 수행한다.
   페이로드가 없으므로 웹 공격/자격증명/DNS 터널링 내용 탐지는 못 한다.

--live 는 권한을 감지해 A가 불가능하면 B로 자동 폴백한다.
"""
from __future__ import annotations

import ctypes
import re
import socket
import statistics
import subprocess
import time
from collections import defaultdict

from . import detect, dnsparse, httpparse
from .detect import Finding, shannon_entropy
from .analyzer import AnalysisData
from .layers import decode
from .pcapio import LINKTYPE_RAW_IP, PcapWriter, RawPacket
from .report import SEV_KO
from .sessions import SessionTable


def is_elevated() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def default_iface_ip() -> str:
    """기본 라우트가 쓰는 로컬 IP (UDP connect 트릭, 패킷은 나가지 않음)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
    finally:
        s.close()


def _print_finding(f: Finding) -> None:
    stamp = time.strftime("%H:%M:%S")
    print(f"\n[{stamp}] ⚠ ({SEV_KO[f.severity]}/{f.category}) {f.title}")
    print(f"           {f.description}")
    for ev in f.evidence[:3]:
        print(f"           증거: {ev}")


# ================================================================ A. 패킷 모드

class PacketCapture:
    """SIO_RCVALL raw socket 캡처. with 문으로 열고 닫는다."""

    def __init__(self, iface_ip: str | None = None):
        self.iface_ip = iface_ip or default_iface_ip()
        self._sock = None

    def __enter__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((self.iface_ip, 0))
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(1.0)  # Ctrl+C가 먹히도록 주기적으로 깨어난다
        self._sock = s
        return self

    def __exit__(self, *exc):
        if self._sock is not None:
            try:
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
            self._sock.close()

    def recv(self) -> bytes | None:
        try:
            return self._sock.recv(65535)
        except socket.timeout:
            return None


class LiveEngine:
    """패킷을 들어오는 대로 적재하고, sweep() 호출 시 새 탐지만 돌려준다.

    파일 분석(analyzer.analyze)과 같은 자료구조를 쓰므로 탐지기는 그대로 재사용된다.
    테스트에서는 소켓 없이 ingest()에 패킷을 직접 주입한다.
    """

    def __init__(self, ioc_path: str | None = None):
        self.data = AnalysisData()
        self.table = SessionTable()
        self.ioc_path = ioc_path
        self.packet_count = 0
        self._seen: set[tuple[str, str]] = set()

    def ingest(self, raw: RawPacket) -> None:
        pkt = decode(raw)
        if pkt is None or not pkt.src:
            return
        self.packet_count += 1
        self.table.feed(pkt)
        if pkt.proto == "udp" and 53 in (pkt.sport, pkt.dport) and pkt.payload:
            msg = dnsparse.parse(pkt.payload)
            if msg is not None and (msg.questions or msg.answers):
                querier = pkt.dst if msg.is_response else pkt.src
                self.data.dns_messages.append((querier, msg))

    def sweep(self) -> list[Finding]:
        # 세션에서 HTTP/FTP 추출을 다시 계산 (라이브 중엔 스트림이 계속 자란다)
        self.data.sessions = self.table.sessions
        self.data.http_transactions = []
        self.data.ftp_streams = []
        for s in self.table.sessions:
            if s.proto != "tcp":
                continue
            c2s = s.stream(c2s=True)
            s2c = s.stream(c2s=False)
            if not c2s and not s2c:
                continue
            if s.sport == 21 or (s2c.startswith(b"220 ") and b"FTP" in s2c[:100].upper()):
                self.data.ftp_streams.append((s, c2s, s2c))
            elif httpparse.looks_like_http(c2s):
                for tx in httpparse.parse_transactions(c2s, s2c):
                    self.data.http_transactions.append((s, tx))
        fresh = []
        for f in detect.run_all(self.data, self.ioc_path):
            key = (f.category, f.title)
            if key not in self._seen:
                self._seen.add(key)
                fresh.append(f)
        return fresh


def run_packet_mode(duration: float, sweep_sec: float, ioc_path: str | None,
                    save_path: str | None) -> LiveEngine:
    engine = LiveEngine(ioc_path)
    writer = PcapWriter(save_path, LINKTYPE_RAW_IP) if save_path else None
    with PacketCapture() as cap:
        print(f"[패킷 모드] {cap.iface_ip} 인터페이스 감시 시작 "
              f"(탐지 스윕 {sweep_sec:.0f}초 주기, Ctrl+C 종료)")
        start = last_sweep = time.time()
        number = 0
        try:
            while True:
                now = time.time()
                if duration and now - start >= duration:
                    break
                data = cap.recv()
                if data:
                    number += 1
                    ts = time.time()
                    engine.ingest(RawPacket(ts, data, len(data), LINKTYPE_RAW_IP, number))
                    if writer:
                        writer.write(ts, data)
                if now - last_sweep >= sweep_sec:
                    last_sweep = now
                    for f in engine.sweep():
                        _print_finding(f)
                    print(f"  … 패킷 {engine.packet_count:,} / 세션 {len(engine.table.sessions)}",
                          end="\r")
        except KeyboardInterrupt:
            print("\n중단됨 — 최종 스윕 실행")
        for f in engine.sweep():
            _print_finding(f)
        if writer:
            writer.close()
            print(f"\n증거 pcap 저장: {save_path} ({writer.count:,} packets) — "
                  f"파일 모드로 재분석 가능")
    return engine


# ================================================================ B. 플로우 모드

NETSTAT_RE = re.compile(
    r"^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)\s*$")


def parse_netstat(text: str) -> list[tuple[str, int, str, int, str, int]]:
    """netstat -ano -p tcp 출력 -> [(lip, lport, rip, rport, state, pid)]"""
    rows = []
    for line in text.splitlines():
        m = NETSTAT_RE.match(line)
        if m:
            rows.append((m.group(1), int(m.group(2)), m.group(3),
                         int(m.group(4)), m.group(5), int(m.group(6))))
    return rows


class FlowMonitor:
    """연결 테이블 + DNS 캐시 폴링 기반 경량 탐지 (승격 불필요)."""

    def __init__(self, ioc_path: str | None = None,
                 beacon_min_events: int = 6, beacon_max_cv: float = 0.2):
        self.conn_events = defaultdict(list)   # (rip, rport) -> [등장 시각]
        self.syn_ports = defaultdict(set)      # rip -> {rport} (SYN_SENT 누적)
        self.syn_hosts = defaultdict(set)      # rport -> {rip}
        self.known = set()                     # 현재 떠 있는 (lport, rip, rport)
        self.seen_domains = set()
        self.beacon_min_events = beacon_min_events
        self.beacon_max_cv = beacon_max_cv
        self._seen_findings = set()
        self.ioc_ips, self.ioc_domains = set(), set()
        if ioc_path:
            self._load_ioc(ioc_path)

    def _load_ioc(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if re.fullmatch(r"[0-9.]+(/\d+)?", line):
                        self.ioc_ips.add(line.split("/")[0])  # 플로우 모드는 단일 IP만
                    else:
                        self.ioc_domains.add(line.lower().rstrip("."))
        except OSError:
            pass

    # --- 입력 수집 ---------------------------------------------------------

    def poll_connections(self, now: float, netstat_text: str | None = None) -> None:
        if netstat_text is None:
            netstat_text = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            ).stdout
        current = set()
        for lip, lport, rip, rport, state, pid in parse_netstat(netstat_text):
            if rip in ("0.0.0.0", "127.0.0.1", "*") or state == "LISTENING":
                continue
            key = (lport, rip, rport)
            current.add(key)
            if state == "SYN_SENT":
                self.syn_ports[rip].add(rport)
                self.syn_hosts[rport].add(rip)
            elif state == "ESTABLISHED" and key not in self.known:
                self.conn_events[(rip, rport)].append(now)  # 새 연결 등장
        self.known = current

    def poll_dns_cache(self, entries: list[str] | None = None) -> None:
        if entries is None:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-DnsClientCache | Select-Object -ExpandProperty Entry"],
                capture_output=True, text=True, creationflags=0x08000000,
            ).stdout
            entries = out.split()
        for name in entries:
            self.seen_domains.add(name.lower().rstrip("."))

    # --- 탐지 --------------------------------------------------------------

    def sweep(self) -> list[Finding]:
        out = []
        # 비커닝: 같은 원격지에 새 연결이 규칙적 간격으로 반복
        for (rip, rport), times in self.conn_events.items():
            if len(times) < self.beacon_min_events:
                continue
            gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
            if len(gaps) < self.beacon_min_events - 1:
                continue
            mean = statistics.fmean(gaps)
            cv = statistics.pstdev(gaps) / mean if mean > 0 else 99
            if mean >= 5 and cv <= self.beacon_max_cv:
                out.append(Finding(
                    "high", "c2", f"C2 비커닝 의심(라이브): {rip}:{rport}",
                    f"평균 {mean:.1f}초 간격으로 새 연결 {len(times)}회. "
                    f"간격 변동계수 {cv:.3f}.",
                    evidence=[f"연결 시각 수: {len(times)}"],
                    mitre="T1071", recommendation=f"{rip} 평판 조회, 연결 PID의 프로세스 확인"))
        # 아웃바운드 스캔 흔적: SYN_SENT가 많은 포트/호스트로 흩어짐
        for rip, ports in self.syn_ports.items():
            if len(ports) >= 15:
                out.append(Finding(
                    "high", "recon", f"이 호스트발 포트 스캔 의심: -> {rip}",
                    f"{rip} 의 서로 다른 포트 {len(ports)}개로 연결 시도(SYN_SENT)가 "
                    f"관찰되었습니다. 이 PC의 프로세스가 스캔 중일 수 있습니다.",
                    mitre="T1046", recommendation="netstat -ano로 해당 PID 추적"))
        for rport, hosts in self.syn_hosts.items():
            if len(hosts) >= 10:
                out.append(Finding(
                    "medium", "recon", f"이 호스트발 호스트 스윕 의심: 포트 {rport}",
                    f"포트 {rport} 로 호스트 {len(hosts)}대에 연결을 시도했습니다.",
                    mitre="T1018", recommendation="스캐너/백업 등 정상 소프트웨어 여부 확인"))
        # IOC 접촉
        for (rip, rport), times in self.conn_events.items():
            if rip in self.ioc_ips:
                out.append(Finding(
                    "critical", "ioc", f"IOC IP 접촉(라이브): {rip}:{rport}",
                    f"침해지표 IP와의 연결이 {len(times)}회 관찰되었습니다.",
                    mitre="-", recommendation="즉시 네트워크 격리 검토"))
        for name in self.seen_domains:
            for d in self.ioc_domains:
                if name == d or name.endswith("." + d):
                    out.append(Finding(
                        "critical", "ioc", f"IOC 도메인 캐시 발견: {name}",
                        f"침해지표 도메인 '{d}' 이 DNS 캐시에 있습니다 (최근 접촉 흔적).",
                        mitre="-", recommendation="ipconfig /displaydns 로 TTL 확인, 접속 프로세스 추적"))
        # DGA 의심 캐시: 고엔트로피 무작위형 이름 다수
        dga = [n for n in self.seen_domains
               if "." in n and not n.endswith(".in-addr.arpa")
               and len(n.split(".")[0]) >= 12
               and shannon_entropy(n.split(".")[0]) >= 3.2]
        if len(dga) >= 15:
            out.append(Finding(
                "medium", "c2", "DGA 의심 도메인 다수 캐시됨",
                f"무작위 생성형 이름 {len(dga)}개가 DNS 캐시에서 발견되었습니다.",
                evidence=[f"예시: {', '.join(sorted(dga)[:5])}"],
                mitre="T1568.002", recommendation="캐시를 비우고 재발 여부 관찰"))
        fresh = []
        for f in out:
            key = (f.category, f.title)
            if key not in self._seen_findings:
                self._seen_findings.add(key)
                fresh.append(f)
        return fresh


def run_flow_mode(duration: float, sweep_sec: float, ioc_path: str | None) -> FlowMonitor:
    mon = FlowMonitor(ioc_path)
    print(f"[플로우 모드] 연결 테이블·DNS 캐시 폴링 시작 "
          f"(탐지 스윕 {sweep_sec:.0f}초 주기, Ctrl+C 종료)")
    print("  ※ 승격 없이 동작하는 축소 모드: 비커닝·스캔·IOC·DGA 캐시만 탐지")
    start = time.time()
    last_dns = 0.0
    try:
        while True:
            now = time.time()
            if duration and now - start >= duration:
                break
            mon.poll_connections(now)
            if now - last_dns >= 30:
                last_dns = now
                mon.poll_dns_cache()
            for f in mon.sweep():
                _print_finding(f)
            print(f"  … 추적 연결 {len(mon.known)} / 원격지 {len(mon.conn_events)} "
                  f"/ 캐시 도메인 {len(mon.seen_domains)}", end="\r")
            time.sleep(min(sweep_sec, 2.0))
    except KeyboardInterrupt:
        print("\n중단됨")
    return mon


# ================================================================ 진입점

def run_live(mode: str, duration: float, sweep_sec: float,
             ioc_path: str | None, save_path: str | None) -> int:
    print("live-pcap_forensics_analyzer — 실시간 탐지")
    print("⚠ 본인 소유/관리 호스트의 트래픽 모니터링 용도로만 사용하세요.\n")
    if mode == "auto":
        mode = "packet" if is_elevated() else "flow"
        if mode == "flow":
            print("관리자 권한이 아니므로 플로우 모드로 동작합니다.")
            print("패킷 모드를 쓰려면 터미널을 '관리자 권한으로 실행' 후 다시 실행하세요.\n")
    if mode == "packet":
        if not is_elevated():
            print("오류: 패킷 모드는 관리자 권한 세션이 필요합니다.")
            return 1
        engine = run_packet_mode(duration, sweep_sec, ioc_path, save_path)
        n = len(engine._seen)
    else:
        mon = run_flow_mode(duration, sweep_sec, ioc_path)
        n = len(mon._seen_findings)
    print(f"\n종료 — 누적 탐지 {n}건")
    return 2 if n else 0
