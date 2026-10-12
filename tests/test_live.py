"""라이브 모드 단위 테스트.

실제 소켓/승격 없이 검증한다:
- 플로우 모드: netstat 출력·DNS 캐시 목록을 직접 주입
- 패킷 모드 엔진: raw-IP 패킷(LINKTYPE_RAW_IP)을 ingest()에 직접 주입
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from live_pcap_forensics_analyzer import craft
from live_pcap_forensics_analyzer.live import FlowMonitor, LiveEngine, parse_netstat
from live_pcap_forensics_analyzer.pcapio import LINKTYPE_RAW_IP, RawPacket

NETSTAT_SAMPLE = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1660
  TCP    192.168.0.5:52001      93.184.216.34:443      ESTABLISHED     4242
  TCP    192.168.0.5:52002      10.9.9.9:8080          SYN_SENT        4242
"""


def _netstat_row(lport, rip, rport, state, pid=999):
    return (f"  TCP    192.168.0.5:{lport}      {rip}:{rport}      "
            f"{state}       {pid}")


def _netstat_text(rows):
    return "Active Connections\n\n  Proto ...\n" + "\n".join(rows) + "\n"


class TestParseNetstat(unittest.TestCase):
    def test_parse(self):
        rows = parse_netstat(NETSTAT_SAMPLE)
        self.assertIn(("192.168.0.5", 52001, "93.184.216.34", 443, "ESTABLISHED", 4242), rows)
        self.assertIn(("192.168.0.5", 52002, "10.9.9.9", 8080, "SYN_SENT", 4242), rows)
        # LISTENING 줄도 파싱은 되고, 필터링은 FlowMonitor 몫
        self.assertEqual(len(rows), 3)


class TestFlowMonitor(unittest.TestCase):
    def test_beacon_on_regular_reconnects(self):
        mon = FlowMonitor()
        present = _netstat_text([_netstat_row(53000, "198.51.100.7", 443, "ESTABLISHED")])
        absent = _netstat_text([])
        t = 1000.0
        for i in range(7):  # 20초 간격으로 7회 등장
            mon.poll_connections(t, present)
            mon.poll_connections(t + 10, absent)
            t += 20
        findings = mon.sweep()
        self.assertTrue(any("비커닝" in f.title for f in findings))
        self.assertEqual(mon.sweep(), [])  # 중복 보고 없음

    def test_outbound_portscan(self):
        mon = FlowMonitor()
        rows = [_netstat_row(53000 + p, "10.0.0.9", 1000 + p, "SYN_SENT") for p in range(16)]
        mon.poll_connections(1.0, _netstat_text(rows))
        findings = mon.sweep()
        self.assertTrue(any("포트 스캔" in f.title for f in findings))

    def test_ioc_ip_and_domain(self):
        ioc = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w",
                                          encoding="utf-8")
        ioc.write("203.0.113.99\nevil-c2.example\n")
        ioc.close()
        try:
            mon = FlowMonitor(ioc_path=ioc.name)
        finally:
            os.unlink(ioc.name)
        mon.poll_connections(1.0, _netstat_text(
            [_netstat_row(53000, "203.0.113.99", 443, "ESTABLISHED")]))
        mon.poll_dns_cache(["www.evil-c2.example", "www.naver.com"])
        titles = [f.title for f in mon.sweep()]
        self.assertTrue(any("IOC IP" in t for t in titles))
        self.assertTrue(any("IOC 도메인" in t for t in titles))

    def test_dga_cache(self):
        mon = FlowMonitor()
        import random
        import string
        r = random.Random(7)
        names = ["".join(r.choices(string.ascii_lowercase + string.digits, k=14)) + ".com"
                 for _ in range(20)]
        mon.poll_dns_cache(names)
        findings = mon.sweep()
        self.assertTrue(any("DGA" in f.title for f in findings))

    def test_normal_traffic_no_findings(self):
        mon = FlowMonitor()
        mon.poll_connections(1.0, NETSTAT_SAMPLE)
        mon.poll_dns_cache(["www.naver.com", "github.githubassets.com"])
        self.assertEqual(mon.sweep(), [])


class TestLiveEngine(unittest.TestCase):
    def _raw_ip(self, ts, src, dst, sport, dport, flags, payload=b"", num=1):
        ip = craft.ipv4(src, dst, 6, craft.tcp(sport, dport, 1, 0, flags, payload))
        return RawPacket(ts, ip, len(ip), LINKTYPE_RAW_IP, num)

    def test_portscan_detected_from_raw_ip_packets(self):
        eng = LiveEngine()
        for i in range(16):
            eng.ingest(self._raw_ip(1.0 + i * 0.01, "10.0.0.66", "10.0.0.10",
                                    50000 + i, 100 + i, craft.TCP_SYN, num=i + 1))
        findings = eng.sweep()
        self.assertTrue(any(f.category == "recon" for f in findings))
        self.assertEqual(eng.sweep(), [])  # 같은 탐지는 한 번만

    def test_dns_message_collected(self):
        eng = LiveEngine()
        ip = craft.ipv4("10.0.0.5", "8.8.8.8", 17,
                        craft.udp(40000, 53, craft.dns_query("www.example.com")))
        eng.ingest(RawPacket(1.0, ip, len(ip), LINKTYPE_RAW_IP, 1))
        self.assertEqual(len(eng.data.dns_messages), 1)
        self.assertEqual(eng.data.dns_messages[0][0], "10.0.0.5")


if __name__ == "__main__":
    unittest.main()
