"""라이브 모드 단위 테스트.

실제 소켓/승격 없이 검증한다: raw-IP 패킷(LINKTYPE_RAW_IP)을
LiveEngine.ingest()에 직접 주입해 파이프라인 재사용 경로를 확인.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from live_pcap_forensics_analyzer import craft
from live_pcap_forensics_analyzer.live import LiveEngine
from live_pcap_forensics_analyzer.pcapio import LINKTYPE_RAW_IP, RawPacket


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

    def test_normal_traffic_no_findings(self):
        eng = LiveEngine()
        # 평범한 HTTPS 연결 몇 개 — 탐지가 나오면 안 된다
        for i in range(3):
            eng.ingest(self._raw_ip(1.0 + i, "10.0.0.5", "93.184.216.34",
                                    50000 + i, 443, craft.TCP_SYN, num=i + 1))
        self.assertEqual(eng.sweep(), [])


if __name__ == "__main__":
    unittest.main()
