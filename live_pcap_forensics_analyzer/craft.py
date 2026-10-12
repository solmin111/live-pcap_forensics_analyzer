"""테스트/시연용 패킷 크래프팅.

이 PC처럼 Npcap/Wireshark 가 없는 환경에서도 분석기를 검증할 수 있도록
Ethernet/ARP/IPv4/TCP/UDP 프레임을 바이트로 직접 만들어 pcap 으로 저장한다.
분석기는 체크섬을 검증하지 않으므로 체크섬은 0으로 둔다.
"""
from __future__ import annotations

import struct
from ipaddress import ip_address

from .layers import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN  # noqa: F401 (재노출)

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def _ip_bytes(ip: str) -> bytes:
    return ip_address(ip).packed


def ethernet(src: str, dst: str, etype: int, payload: bytes) -> bytes:
    return _mac_bytes(dst) + _mac_bytes(src) + struct.pack("!H", etype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s",
                      0x45, 0, total, 0, 0, ttl, proto, 0,
                      _ip_bytes(src), _ip_bytes(dst))
    return hdr + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
    return hdr + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def arp_reply(sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    body = struct.pack("!HHBBH", 1, ETH_IPV4, 6, 4, 2)
    body += _mac_bytes(sender_mac) + _ip_bytes(sender_ip)
    body += _mac_bytes(target_mac) + _ip_bytes(target_ip)
    return ethernet(sender_mac, target_mac, ETH_ARP, body)


def dns_query(name: str, qtype: int = 1, txid: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def dns_response(name: str, qtype: int = 1, rcode: int = 0,
                 answer_ip: str | None = None, txid: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    ancount = 1 if answer_ip else 0
    msg = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, ancount, 0, 0)
    msg += q + struct.pack("!HH", qtype, 1)
    if answer_ip:
        # 이름은 압축 포인터(0xC00C)로 질문부를 가리킨다
        msg += struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + _ip_bytes(answer_ip)
    return msg


class TcpFlow:
    """양방향 TCP 대화를 올바른 seq/ack 로 만들어 주는 헬퍼.

    사용법:
        flow = TcpFlow(pkts, "10.0.0.5", 49152, "10.0.0.80", 80)
        flow.handshake(t)
        flow.send(t, b"GET / HTTP/1.1...")      # 클라이언트 -> 서버
        flow.send(t, b"HTTP/1.1 200 ...", c2s=False)
        flow.close(t)
    """

    def __init__(self, out: list, cip: str, cport: int, sip: str, sport: int,
                 cmac: str = "aa:aa:aa:aa:aa:01", smac: str = "aa:aa:aa:aa:aa:02"):
        self.out = out
        self.c = (cip, cport, cmac)
        self.s = (sip, sport, smac)
        self.cseq = 1000
        self.sseq = 5000

    def _emit(self, ts: float, c2s: bool, flags: int, payload: bytes = b""):
        src, sport, smac = self.c if c2s else self.s
        dst, dport, dmac = self.s if c2s else self.c
        seq = self.cseq if c2s else self.sseq
        ack = self.sseq if c2s else self.cseq
        seg = tcp(sport, dport, seq, ack, flags, payload)
        self.out.append((ts, ethernet(smac, dmac, ETH_IPV4, ipv4(src, dst, 6, seg))))
        adv = len(payload) + (1 if flags & (TCP_SYN | TCP_FIN) else 0)
        if c2s:
            self.cseq += adv
        else:
            self.sseq += adv

    def handshake(self, ts: float):
        self._emit(ts, True, TCP_SYN)
        self._emit(ts + 0.001, False, TCP_SYN | TCP_ACK)
        self._emit(ts + 0.002, True, TCP_ACK)

    def send(self, ts: float, payload: bytes, c2s: bool = True, mss: int = 1400):
        for i in range(0, len(payload), mss):
            self._emit(ts + i / 1e7, c2s, TCP_PSH | TCP_ACK, payload[i : i + mss])

    def close(self, ts: float):
        self._emit(ts, True, TCP_FIN | TCP_ACK)
        self._emit(ts + 0.001, False, TCP_FIN | TCP_ACK)
        self._emit(ts + 0.002, True, TCP_ACK)

    def reset(self, ts: float, c2s: bool = False):
        self._emit(ts, c2s, TCP_RST | TCP_ACK)


def syn_probe(out: list, ts: float, src: str, dst: str, sport: int, dport: int,
              smac: str = "aa:aa:aa:aa:aa:01", dmac: str = "aa:aa:aa:aa:aa:02"):
    """응답 없는 SYN 1개 (스캔용)."""
    seg = tcp(sport, dport, 1, 0, TCP_SYN)
    out.append((ts, ethernet(smac, dmac, ETH_IPV4, ipv4(src, dst, 6, seg))))


def udp_packet(out: list, ts: float, src: str, dst: str, sport: int, dport: int,
               payload: bytes, smac: str = "aa:aa:aa:aa:aa:01",
               dmac: str = "aa:aa:aa:aa:aa:02"):
    out.append((ts, ethernet(smac, dmac, ETH_IPV4, ipv4(src, dst, 17, udp(sport, dport, payload)))))
