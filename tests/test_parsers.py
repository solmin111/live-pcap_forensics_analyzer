"""파서 계층 단위 테스트: pcap/pcapng 리더, DNS, HTTP, TCP 재조립."""
import gzip
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from live_pcap_forensics_analyzer import craft, dnsparse, httpparse
from live_pcap_forensics_analyzer.layers import decode
from live_pcap_forensics_analyzer.pcapio import RawPacket, read_packets, write_pcap
from live_pcap_forensics_analyzer.sessions import SessionTable


def _tmp(data: bytes) -> str:
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    f.write(data)
    f.close()
    return f.name


class TestPcapIO(unittest.TestCase):
    def test_pcap_roundtrip(self):
        frame = craft.ethernet("aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02", 0x0800,
                               craft.ipv4("10.0.0.1", "10.0.0.2", 6,
                                          craft.tcp(1234, 80, 1, 0, craft.TCP_SYN)))
        path = _tmp(b"")
        write_pcap(path, [(1700000000.123456, frame)])
        pkts = list(read_packets(path))
        os.unlink(path)
        self.assertEqual(len(pkts), 1)
        self.assertAlmostEqual(pkts[0].ts, 1700000000.123456, places=5)
        self.assertEqual(pkts[0].data, frame)

    def test_pcap_big_endian_and_nanosecond(self):
        # 빅엔디언 + 나노초 매직 헤더를 손으로 만든다
        hdr = struct.pack(">IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
        rec = struct.pack(">IIII", 100, 500_000_000, 4, 4) + b"\x01\x02\x03\x04"
        path = _tmp(hdr + rec)
        pkts = list(read_packets(path))
        os.unlink(path)
        self.assertEqual(len(pkts), 1)
        self.assertAlmostEqual(pkts[0].ts, 100.5, places=6)

    def test_truncated_tail_is_tolerated(self):
        frame = b"\x00" * 20
        path = _tmp(b"")
        write_pcap(path, [(1.0, frame)])
        with open(path, "ab") as f:
            f.write(b"\xde\xad")  # 잘린 레코드 헤더
        pkts = list(read_packets(path))
        os.unlink(path)
        self.assertEqual(len(pkts), 1)

    def test_pcapng_epb(self):
        # SHB + IDB + EPB 를 직접 구성
        def block(btype: int, body: bytes) -> bytes:
            total = 12 + len(body)  # 타입(4) + 길이(4) + 본문 + 꼬리 길이(4)
            return struct.pack("<II", btype, total) + body + struct.pack("<I", total)

        shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        idb = block(1, struct.pack("<HHI", 1, 0, 65535))
        data = b"\xaa\xbb\xcc\xdd"
        ts = 1_700_000_000_000_000  # 마이크로초 단위 64비트
        epb = block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, 4, 4) + data)
        path = _tmp(shb + idb + epb)
        pkts = list(read_packets(path))
        os.unlink(path)
        self.assertEqual(len(pkts), 1)
        self.assertEqual(pkts[0].data, data)
        self.assertAlmostEqual(pkts[0].ts, 1_700_000_000.0, places=3)


class TestLayers(unittest.TestCase):
    def test_tcp_decode(self):
        frame = craft.ethernet("aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02", 0x0800,
                               craft.ipv4("10.0.0.1", "10.0.0.2", 6,
                                          craft.tcp(1234, 80, 7, 0,
                                                    craft.TCP_SYN, b"hi")))
        pkt = decode(RawPacket(1.0, frame, len(frame), 1, 1))
        self.assertEqual((pkt.src, pkt.dst, pkt.proto), ("10.0.0.1", "10.0.0.2", "tcp"))
        self.assertEqual((pkt.sport, pkt.dport, pkt.seq), (1234, 80, 7))
        self.assertTrue(pkt.flag(craft.TCP_SYN))
        self.assertEqual(pkt.payload, b"hi")

    def test_vlan_tag_is_stripped(self):
        inner = craft.ipv4("10.0.0.1", "10.0.0.2", 17, craft.udp(53, 53, b"x"))
        tagged = (bytes.fromhex("aaaaaaaaaa02") + bytes.fromhex("aaaaaaaaaa01")
                  + struct.pack("!HH", 0x8100, 100)  # VLAN 100
                  + struct.pack("!H", 0x0800) + inner)
        pkt = decode(RawPacket(1.0, tagged, len(tagged), 1, 1))
        self.assertEqual(pkt.vlan, 100)
        self.assertEqual(pkt.proto, "udp")

    def test_arp_decode(self):
        frame = craft.arp_reply("de:ad:be:ef:00:01", "192.168.0.1",
                                "aa:bb:cc:dd:ee:ff", "192.168.0.2")
        pkt = decode(RawPacket(1.0, frame, len(frame), 1, 1))
        self.assertIsNotNone(pkt.arp)
        self.assertEqual(pkt.arp.op, 2)
        self.assertEqual(pkt.arp.sender_ip, "192.168.0.1")


class TestDns(unittest.TestCase):
    def test_query_and_compressed_answer(self):
        payload = craft.dns_response("www.example.com", answer_ip="1.2.3.4")
        msg = dnsparse.parse(payload)
        self.assertTrue(msg.is_response)
        self.assertEqual(msg.questions, [("www.example.com", "A")])
        self.assertEqual(msg.answers[0], ("www.example.com", "A", "1.2.3.4"))

    def test_nxdomain(self):
        msg = dnsparse.parse(craft.dns_response("no.such.domain", rcode=3))
        self.assertEqual(msg.rcode, 3)

    def test_pointer_loop_does_not_hang(self):
        # 자기 자신을 가리키는 포인터: parse_name이 중단해야 한다
        evil = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
        msg = dnsparse.parse(evil)  # 예외/무한루프 없이 반환되면 통과
        self.assertIsNotNone(msg)


class TestHttp(unittest.TestCase):
    def test_chunked_gzip_response(self):
        body = gzip.compress(b"<html>secret</html>")
        chunk = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        s2c = (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
               b"Transfer-Encoding: chunked\r\n\r\n" + chunk)
        c2s = b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
        txs = httpparse.parse_transactions(c2s, s2c)
        self.assertEqual(len(txs), 1)
        self.assertEqual(txs[0].response.body, b"<html>secret</html>")

    def test_pipelined_requests(self):
        c2s = (b"GET /1 HTTP/1.1\r\nHost: x\r\n\r\n"
               b"GET /2 HTTP/1.1\r\nHost: x\r\n\r\n")
        s2c = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
               b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        txs = httpparse.parse_transactions(c2s, s2c)
        self.assertEqual([t.request.uri for t in txs], ["/1", "/2"])
        self.assertEqual([t.response.status for t in txs], [200, 404])

    def test_post_body(self):
        c2s = (b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 7\r\n\r\npw=1234")
        txs = httpparse.parse_transactions(c2s, b"")
        self.assertEqual(txs[0].request.body, b"pw=1234")


class TestReassembly(unittest.TestCase):
    def _packets_out_of_order(self):
        pkts = []
        flow = craft.TcpFlow(pkts, "10.0.0.1", 40000, "10.0.0.2", 80)
        flow.handshake(1.0)
        flow.send(1.1, b"AAAA")
        flow.send(1.2, b"BBBB")
        flow.send(1.3, b"CCCC")
        # 데이터 3개(인덱스 3,4,5)의 순서를 섞고 중복(재전송)도 끼운다
        order = [0, 1, 2, 5, 3, 4, 3]
        return [pkts[i] for i in order]

    def test_out_of_order_and_retransmit(self):
        table = SessionTable()
        for i, (ts, frame) in enumerate(self._packets_out_of_order(), 1):
            pkt = decode(RawPacket(ts, frame, len(frame), 1, i))
            table.feed(pkt)
        self.assertEqual(table.count, 1)
        self.assertEqual(table.sessions[0].stream(c2s=True), b"AAAABBBBCCCC")


if __name__ == "__main__":
    unittest.main()
