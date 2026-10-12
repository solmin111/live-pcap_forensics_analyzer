"""탐지 엔진: 세션/HTTP/DNS/ARP 데이터를 받아 Finding 목록을 만든다.

각 탐지기는 독립 함수이고, analyzer 가 모은 AnalysisData 하나를 입력으로 받는다.
임계값은 THRESHOLDS 로 한 곳에 모아 과제 중 튜닝하기 쉽게 했다.
"""
from __future__ import annotations

import base64
import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from urllib.parse import unquote_plus

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

THRESHOLDS = {
    "portscan_min_ports": 15,      # 한 src가 건드린 서로 다른 포트 수
    "hostscan_min_hosts": 10,      # 한 src가 같은 포트로 건드린 호스트 수
    "brute_min_attempts": 8,       # 같은 서비스에 대한 로그인 실패/짧은 연결 수
    "dns_min_queries": 20,         # 터널링 판단 최소 질의 수
    "dns_label_len": 30,           # 의심 서브도메인 평균 길이
    "dns_entropy": 3.5,            # 서브도메인 샤논 엔트로피
    "beacon_min_events": 8,        # 비커닝 판단 최소 연결 수
    "beacon_max_cv": 0.15,         # 간격 변동계수(낮을수록 기계적)
    "beacon_min_interval": 2.0,    # 초
}


@dataclass
class Finding:
    severity: str          # critical | high | medium | low | info
    category: str          # recon | bruteforce | webattack | credential | c2 | spoofing | ioc
    title: str
    description: str
    evidence: list = field(default_factory=list)   # 사람이 읽을 증거 문자열들
    mitre: str = ""                                 # MITRE ATT&CK 기법 ID
    recommendation: str = ""
    session_ids: list = field(default_factory=list)

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def run_all(data, ioc_path: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for det in (
        detect_port_scan, detect_host_scan, detect_bruteforce,
        detect_cleartext_credentials, detect_web_attacks,
        detect_dns_tunneling, detect_beaconing, detect_arp_spoofing,
    ):
        findings.extend(det(data))
    if ioc_path:
        findings.extend(detect_ioc(data, ioc_path))
    findings.sort(key=lambda f: -f.rank)
    return findings


# ---------------------------------------------------------------- 정찰

def detect_port_scan(data) -> list[Finding]:
    out = []
    # src -> dst -> {미완성 연결의 dst 포트}
    probes = defaultdict(lambda: defaultdict(set))
    for s in data.sessions:
        if s.proto == "tcp" and s.syn_seen and not s.synack_seen and s.bytes_s2c == 0:
            probes[s.client][s.server].add(s.sport)
    for src, by_dst in probes.items():
        for dst, ports in by_dst.items():
            if len(ports) >= THRESHOLDS["portscan_min_ports"]:
                sample = sorted(ports)[:12]
                out.append(Finding(
                    "high", "recon",
                    f"포트 스캔 의심: {src} -> {dst}",
                    f"{src} 가 {dst} 의 서로 다른 포트 {len(ports)}개에 SYN을 보냈지만 "
                    f"응답 데이터가 없는 미완성 연결입니다.",
                    evidence=[f"대상 포트 예시: {', '.join(map(str, sample))} ..."],
                    mitre="T1046 (Network Service Discovery)",
                    recommendation="해당 출발지 IP 차단 여부 검토, 스캔 이후 성공한 연결이 있는지 추적",
                ))
    return out


def detect_host_scan(data) -> list[Finding]:
    out = []
    sweep = defaultdict(lambda: defaultdict(set))  # src -> port -> {hosts}
    for s in data.sessions:
        if s.proto == "tcp" and s.syn_seen and not s.synack_seen:
            sweep[s.client][s.sport].add(s.server)
    for src, by_port in sweep.items():
        for port, hosts in by_port.items():
            if len(hosts) >= THRESHOLDS["hostscan_min_hosts"]:
                out.append(Finding(
                    "medium", "recon",
                    f"호스트 스윕 의심: {src} (포트 {port})",
                    f"{src} 가 포트 {port} 로 호스트 {len(hosts)}대를 차례로 접촉했습니다. "
                    f"내부망 수평 이동 전 정찰 패턴입니다.",
                    evidence=[f"대상 호스트 예시: {', '.join(sorted(hosts)[:8])} ..."],
                    mitre="T1018 (Remote System Discovery)",
                    recommendation="출발지 호스트의 감염 여부 점검",
                ))
    return out


# ---------------------------------------------------------------- 계정 공격

def detect_bruteforce(data) -> list[Finding]:
    out = []
    # FTP: 530 응답 수 세기
    fail_by_attacker = defaultdict(int)
    for sess, c2s, s2c in data.ftp_streams:
        fails = s2c.count(b"530")
        if fails:
            fail_by_attacker[(sess.client, sess.server)] += fails
    for (src, dst), fails in fail_by_attacker.items():
        if fails >= THRESHOLDS["brute_min_attempts"]:
            out.append(Finding(
                "high", "bruteforce",
                f"FTP 브루트포스 의심: {src} -> {dst}",
                f"로그인 실패(530) 응답이 {fails}회 관찰되었습니다.",
                evidence=[f"실패 횟수: {fails}"],
                mitre="T1110 (Brute Force)",
                recommendation="해당 계정 잠금/비밀번호 변경, 출발지 차단",
            ))
    # HTTP: 같은 URI에 401/403 반복
    auth_fail = defaultdict(int)
    for sess, tx in data.http_transactions:
        if tx.response and tx.response.status in (401, 403) and tx.request:
            auth_fail[(sess.client, sess.server, tx.request.uri)] += 1
    for (src, dst, uri), n in auth_fail.items():
        if n >= THRESHOLDS["brute_min_attempts"]:
            out.append(Finding(
                "high", "bruteforce",
                f"HTTP 인증 브루트포스 의심: {src} -> {dst}{uri}",
                f"동일 경로에 인증 실패 응답이 {n}회 반복되었습니다.",
                evidence=[f"경로: {uri}", f"실패 횟수: {n}"],
                mitre="T1110.001 (Password Guessing)",
                recommendation="계정 잠금 정책·레이트 리밋 적용 검토",
            ))
    # SSH/Telnet/RDP: 같은 서비스로 짧은 연결 다수
    quick = defaultdict(int)
    for s in data.sessions:
        if s.proto == "tcp" and s.sport in (22, 23, 3389) and s.synack_seen:
            if s.duration < 10 and (s.fin_seen or s.rst_seen):
                quick[(s.client, s.server, s.sport)] += 1
    for (src, dst, port), n in quick.items():
        if n >= THRESHOLDS["brute_min_attempts"]:
            svc = {22: "SSH", 23: "Telnet", 3389: "RDP"}[port]
            out.append(Finding(
                "medium", "bruteforce",
                f"{svc} 반복 접속 의심: {src} -> {dst}",
                f"{svc}({port}) 로 짧은 연결이 {n}회 반복되었습니다. "
                f"암호화 구간이라 내용 대신 연결 패턴으로 판단했습니다.",
                evidence=[f"짧은 연결 수: {n}"],
                mitre="T1110 (Brute Force)",
                recommendation="인증 로그와 대조하여 실패 로그인 확인",
            ))
    return out


# ---------------------------------------------------------------- 자격증명 노출

def detect_cleartext_credentials(data) -> list[Finding]:
    out = []
    for sess, c2s, s2c in data.ftp_streams:
        user = re.search(rb"USER (\S+)", c2s)
        pw = re.search(rb"PASS (\S+)", c2s)
        # 로그인에 성공(230)한 세션만 보고한다. 실패 시도는 브루트포스 탐지가 맡는다.
        if user and pw and b"230" in s2c:
            out.append(Finding(
                "high", "credential",
                f"FTP 평문 자격증명 노출: {sess.key_str}",
                "FTP 로그인 정보가 암호화 없이 전송되었습니다.",
                evidence=[
                    f"USER: {user.group(1).decode('latin-1')}",
                    f"PASS: {'*' * len(pw.group(1))} (캡처에 평문 존재)",
                ],
                mitre="T1040 (Network Sniffing)",
                recommendation="FTPS/SFTP 전환, 노출된 비밀번호 즉시 변경",
                session_ids=[sess.sid],
            ))
    seen_form = set()
    for sess, tx in data.http_transactions:
        if not tx.request:
            continue
        auth = tx.request.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("latin-1")
                user = decoded.split(":", 1)[0]
            except Exception:
                user = "(디코딩 실패)"
            out.append(Finding(
                "high", "credential",
                f"HTTP Basic 인증 평문 노출: {sess.key_str}",
                "Authorization: Basic 헤더는 base64일 뿐 암호화가 아닙니다.",
                evidence=[f"URI: {tx.request.uri}", f"사용자명: {user}"],
                mitre="T1040 (Network Sniffing)",
                recommendation="HTTPS 적용, 해당 계정 비밀번호 변경",
                session_ids=[sess.sid],
            ))
        if tx.request.method == "POST" and tx.request.body:
            body = unquote_plus(tx.request.body.decode("latin-1", "replace"))
            m = re.search(r"(?:^|&)(passw(?:or)?d|pwd|pass)=([^&\s]+)", body, re.I)
            if m:
                dedup = (sess.client, sess.server, tx.request.uri)
                if dedup in seen_form:
                    continue
                seen_form.add(dedup)
                out.append(Finding(
                    "medium", "credential",
                    f"HTTP 폼 비밀번호 평문 전송: {sess.key_str}",
                    f"POST {tx.request.uri} 본문에 비밀번호 필드가 평문으로 포함되어 있습니다.",
                    evidence=[f"필드명: {m.group(1)}"],
                    mitre="T1040 (Network Sniffing)",
                    recommendation="HTTPS 적용",
                    session_ids=[sess.sid],
                ))
    return out


# ---------------------------------------------------------------- 웹 공격

WEB_ATTACK_RULES = [
    # (이름, 심각도, MITRE, 패턴)  -- URI와 본문 양쪽을 검사한다
    ("SQL 인젝션", "high", "T1190", re.compile(
        r"(union(\s|\+|/\*.*?\*/)+select|'\s*or\s+'?1'?\s*=\s*'?1|sleep\(\d+\)|benchmark\(|information_schema)", re.I)),
    ("XSS(크로스사이트 스크립팅)", "medium", "T1189", re.compile(
        r"(<script[\s>]|javascript:|onerror\s*=|onload\s*=|document\.cookie)", re.I)),
    ("경로 조작/LFI", "high", "T1190", re.compile(
        r"(\.\./){2,}|/etc/passwd|\\windows\\system32|php://(filter|input)", re.I)),
    ("Log4Shell(JNDI 조회)", "critical", "T1190", re.compile(
        r"\$\{jndi:(ldap|rmi|dns)s?://", re.I)),
    ("Shellshock", "critical", "T1190", re.compile(
        r"\(\)\s*\{\s*:?\s*;\s*\}\s*;", re.I)),
    ("명령 주입", "high", "T1190", re.compile(
        r"(;|\||%3b|%7c)\s*(cat|whoami|wget|curl|nc|bash|powershell)(\s|%20|\+)", re.I)),
]


def detect_web_attacks(data) -> list[Finding]:
    out = []
    seen = set()
    for sess, tx in data.http_transactions:
        if not tx.request:
            continue
        haystacks = [unquote_plus(tx.request.uri)]
        if tx.request.body:
            haystacks.append(unquote_plus(tx.request.body.decode("latin-1", "replace")))
        # User-Agent 등 헤더로 들어오는 공격(Log4Shell, Shellshock)도 잡는다
        if tx.request.headers:
            haystacks.append(" ".join(tx.request.headers.values()))
        for name, sev, mitre, rx in WEB_ATTACK_RULES:
            for text in haystacks:
                m = rx.search(text)
                if m:
                    dedup = (name, sess.client, sess.server, tx.request.uri[:80])
                    if dedup in seen:
                        break
                    seen.add(dedup)
                    out.append(Finding(
                        sev, "webattack",
                        f"{name} 시도: {sess.client} -> {sess.server}",
                        f"{tx.request.method} {tx.request.uri[:120]} 에서 공격 패턴이 발견되었습니다.",
                        evidence=[f"일치 문자열: {m.group(0)[:100]}",
                                  f"응답 상태: {tx.response.status if tx.response else '(없음)'}"],
                        mitre=f"{mitre} (Exploit Public-Facing Application)",
                        recommendation="WAF 룰 점검, 해당 엔드포인트 입력 검증 확인, 응답 코드로 성공 여부 판단",
                        session_ids=[sess.sid],
                    ))
                    break
    return out


# ---------------------------------------------------------------- C2 / 유출

def _registered_domain(name: str) -> str:
    parts = name.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def detect_dns_tunneling(data) -> list[Finding]:
    out = []
    by_domain = defaultdict(list)  # 등록 도메인 -> [(질의 호스트, 풀 쿼리네임)]
    txt_count = Counter()
    nx_by_host = defaultdict(set)  # 질의 호스트 -> {NXDOMAIN 난 등록 도메인}
    for src, msg in data.dns_messages:
        for qname, qtype in msg.questions:
            if not qname or "." not in qname:
                continue
            dom = _registered_domain(qname)
            if not msg.is_response:
                by_domain[dom].append((src, qname))
                if qtype == "TXT":
                    txt_count[dom] += 1
            elif msg.rcode == 3:
                nx_by_host[src].add(dom)  # src = 질의를 보냈던 호스트 (analyzer가 보정)
    for dom, queries in by_domain.items():
        if len(queries) < THRESHOLDS["dns_min_queries"]:
            continue
        subs = []
        for _, q in queries:
            sub = q[: -(len(dom) + 1)] if q.endswith("." + dom) else ""
            if sub:
                subs.append(sub)
        if not subs:
            continue
        uniq_ratio = len(set(subs)) / len(subs)
        avg_len = sum(len(s) for s in subs) / len(subs)
        avg_entropy = sum(shannon_entropy(s) for s in subs) / len(subs)
        suspicious = (
            avg_len >= THRESHOLDS["dns_label_len"]
            and avg_entropy >= THRESHOLDS["dns_entropy"]
            and uniq_ratio > 0.8
        )
        if suspicious:
            srcs = sorted({s for s, _ in queries})
            out.append(Finding(
                "critical", "c2",
                f"DNS 터널링 의심: {dom}",
                f"{dom} 으로 질의 {len(queries)}건. 서브도메인 평균 길이 {avg_len:.0f}자, "
                f"평균 엔트로피 {avg_entropy:.2f}, 고유 비율 {uniq_ratio:.0%} — "
                f"데이터를 서브도메인에 인코딩해 내보내는 패턴입니다.",
                evidence=[f"질의 호스트: {', '.join(srcs[:5])}",
                          f"서브도메인 예시: {subs[0][:60]}...",
                          f"TXT 질의 비율: {txt_count[dom]}/{len(queries)}"],
                mitre="T1071.004 (DNS), T1048 (Exfiltration)",
                recommendation="해당 도메인 차단 및 질의 호스트 격리, DNS 로그로 유출량 추정",
            ))
    for host, failed_doms in nx_by_host.items():
        if len(failed_doms) >= THRESHOLDS["dns_min_queries"]:
            avg_ent = sum(shannon_entropy(d.split(".")[0]) for d in failed_doms) / len(failed_doms)
            if avg_ent >= 3.0:  # 무작위 생성 도메인은 엔트로피가 높다
                sample = sorted(failed_doms)[:5]
                out.append(Finding(
                    "high", "c2",
                    f"DGA 의심 (NXDOMAIN 다발): {host}",
                    f"{host} 가 서로 다른 도메인 {len(failed_doms)}개를 질의했지만 모두 "
                    f"존재하지 않았습니다(NXDOMAIN). 도메인 생성 알고리즘(DGA)으로 "
                    f"C2 서버를 찾는 멀웨어 패턴입니다.",
                    evidence=[f"실패 도메인 예시: {', '.join(sample)}",
                              f"평균 엔트로피: {avg_ent:.2f}"],
                    mitre="T1568.002 (Domain Generation Algorithms)",
                    recommendation="질의 호스트의 프로세스/작업 스케줄러 점검",
                ))
    return out


def detect_beaconing(data) -> list[Finding]:
    out = []
    conn_times = defaultdict(list)  # (client, server, port) -> [first_ts]
    for s in data.sessions:
        if s.proto == "tcp":
            conn_times[(s.client, s.server, s.sport)].append(s.first_ts)
    for (src, dst, port), times in conn_times.items():
        if len(times) < THRESHOLDS["beacon_min_events"]:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
        if len(gaps) < THRESHOLDS["beacon_min_events"] - 1:
            continue
        mean = statistics.fmean(gaps)
        if mean < THRESHOLDS["beacon_min_interval"]:
            continue
        cv = statistics.pstdev(gaps) / mean if mean else 99
        if cv <= THRESHOLDS["beacon_max_cv"]:
            out.append(Finding(
                "high", "c2",
                f"C2 비커닝 의심: {src} -> {dst}:{port}",
                f"평균 {mean:.1f}초 간격으로 {len(times)}회 연결 (간격 변동계수 {cv:.3f}). "
                f"사람의 통신은 이렇게 규칙적이지 않습니다.",
                evidence=[f"연결 횟수: {len(times)}", f"평균 간격: {mean:.2f}s", f"CV: {cv:.3f}"],
                mitre="T1071 (Application Layer Protocol), T1573 (Encrypted Channel)",
                recommendation=f"{dst} 평판 조회, 출발 호스트 메모리/자동실행 항목 점검",
            ))
    return out


# ---------------------------------------------------------------- 스푸핑

def detect_arp_spoofing(data) -> list[Finding]:
    out = []
    claims = defaultdict(set)  # IP -> {MAC}
    reply_count = Counter()
    for pkt_arp in data.arp_records:
        if pkt_arp.op == 2:  # reply
            claims[pkt_arp.sender_ip].add(pkt_arp.sender_mac)
            reply_count[(pkt_arp.sender_ip, pkt_arp.sender_mac)] += 1
    for ip, macs in claims.items():
        if len(macs) > 1:
            detail = ", ".join(f"{m}({reply_count[(ip, m)]}회)" for m in sorted(macs))
            out.append(Finding(
                "critical", "spoofing",
                f"ARP 스푸핑 의심: {ip} 를 MAC {len(macs)}개가 주장",
                f"같은 IP에 대해 서로 다른 MAC 주소가 ARP 응답을 보냈습니다. "
                f"중간자(MITM) 공격의 전형적인 흔적입니다.",
                evidence=[f"{ip} <- {detail}"],
                mitre="T1557.002 (ARP Cache Poisoning)",
                recommendation="정적 ARP/DAI(Dynamic ARP Inspection) 적용, 해당 구간 트래픽 전수 조사",
            ))
    return out


# ---------------------------------------------------------------- IOC

def detect_ioc(data, path: str) -> list[Finding]:
    ips, nets, domains = set(), [], set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    if "/" in line:
                        nets.append(ip_network(line, strict=False))
                    else:
                        ips.add(str(ip_address(line)))
                except ValueError:
                    domains.add(line.lower().rstrip("."))
    except OSError as e:
        return [Finding("info", "ioc", "IOC 파일을 읽지 못함", str(e))]

    out = []
    hit_ips = set()
    for s in data.sessions:
        for peer in (s.client, s.server):
            if peer in hit_ips:
                continue
            matched = peer in ips
            if not matched and nets:
                try:
                    addr = ip_address(peer)
                    matched = any(addr in n for n in nets)
                except ValueError:
                    pass
            if matched:
                hit_ips.add(peer)
                out.append(Finding(
                    "critical", "ioc",
                    f"IOC 일치 (IP): {peer}",
                    f"침해지표 목록의 IP가 트래픽에 등장했습니다. 예: {s.key_str}",
                    evidence=[f"세션 수 집계 필요: '{peer}' 로 필터링"],
                    mitre="-",
                    recommendation="해당 IP와 통신한 모든 호스트 격리·점검",
                    session_ids=[s.sid],
                ))
    hit_doms = set()
    for _, msg in data.dns_messages:
        for qname, _ in msg.questions:
            q = qname.lower().rstrip(".")
            for d in domains:
                if (q == d or q.endswith("." + d)) and d not in hit_doms:
                    hit_doms.add(d)
                    out.append(Finding(
                        "critical", "ioc",
                        f"IOC 일치 (도메인): {qname}",
                        f"침해지표 도메인 '{d}' 에 대한 DNS 질의가 관찰되었습니다.",
                        mitre="-",
                        recommendation="질의 호스트 격리, DNS 싱크홀 적용",
                    ))
    return out
