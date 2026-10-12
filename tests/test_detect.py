"""탐지 엔진 종단 테스트: 합성 시나리오 pcap -> analyze -> 기대한 탐지가 나오는가."""
import importlib.util
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcapsleuth.analyzer import analyze
from pcapsleuth.pcapio import write_pcap

# tools/make_samples.py 를 모듈로 로드해 시나리오 생성 함수를 재사용한다
_spec = importlib.util.spec_from_file_location(
    "make_samples",
    os.path.join(os.path.dirname(__file__), "..", "tools", "make_samples.py"),
)
make_samples = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_samples)


def _analyze_scenario(maker, ioc_path=None):
    pkts = maker()
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    f.close()
    write_pcap(f.name, pkts)
    try:
        return analyze(f.name, ioc_path=ioc_path)
    finally:
        os.unlink(f.name)


def _titles(result, category=None):
    return [f.title for f in result.findings if category is None or f.category == category]


class TestDetectors(unittest.TestCase):
    def test_portscan_and_hostsweep(self):
        r = _analyze_scenario(make_samples.make_portscan)
        self.assertTrue(any("포트 스캔" in t for t in _titles(r, "recon")))
        self.assertTrue(any("호스트 스윕" in t for t in _titles(r, "recon")))

    def test_ftp_bruteforce_and_credentials(self):
        r = _analyze_scenario(make_samples.make_ftp_bruteforce)
        self.assertTrue(any("FTP 브루트포스" in t for t in _titles(r, "bruteforce")))
        creds = _titles(r, "credential")
        self.assertEqual(len(creds), 1)  # 성공한 세션 1건만 보고해야 한다
        self.assertIn("FTP 평문 자격증명", creds[0])

    def test_web_attacks(self):
        r = _analyze_scenario(make_samples.make_web_attacks)
        titles = " / ".join(_titles(r, "webattack"))
        for name in ("SQL 인젝션", "XSS", "경로 조작", "Log4Shell", "Shellshock"):
            self.assertIn(name, titles)
        self.assertTrue(any("HTTP Basic" in t for t in _titles(r, "credential")))
        self.assertTrue(any("폼 비밀번호" in t for t in _titles(r, "credential")))
        self.assertTrue(any("브루트포스" in t for t in _titles(r, "bruteforce")))

    def test_dns_tunnel_and_dga(self):
        r = _analyze_scenario(make_samples.make_dns_tunnel)
        self.assertTrue(any("DNS 터널링" in t for t in _titles(r, "c2")))
        self.assertTrue(any("DGA" in t for t in _titles(r, "c2")))
        # 정상 도메인(naver 등)은 탐지에 등장하면 안 된다
        self.assertFalse(any("naver" in t for t in _titles(r)))

    def test_beaconing(self):
        r = _analyze_scenario(make_samples.make_beacon)
        self.assertTrue(any("비커닝" in t for t in _titles(r, "c2")))

    def test_arp_spoofing(self):
        r = _analyze_scenario(make_samples.make_arpspoof)
        self.assertTrue(any("ARP 스푸핑" in t for t in _titles(r, "spoofing")))

    def test_ioc_match(self):
        ioc = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w",
                                          encoding="utf-8")
        ioc.write("# 테스트 IOC\n203.0.113.99\nexample-c2.net\n")
        ioc.close()
        try:
            r = _analyze_scenario(make_samples.make_mixed, ioc_path=ioc.name)
        finally:
            os.unlink(ioc.name)
        ioc_titles = _titles(r, "ioc")
        self.assertTrue(any("203.0.113.99" in t for t in ioc_titles))
        self.assertTrue(any("example-c2.net" in t for t in ioc_titles))

    def test_mixed_has_no_false_category_explosion(self):
        r = _analyze_scenario(make_samples.make_mixed)
        cats = {f.category for f in r.findings}
        self.assertEqual(
            cats, {"recon", "bruteforce", "webattack", "credential", "c2", "spoofing"}
        )
        self.assertEqual(r.max_severity, "critical")


if __name__ == "__main__":
    unittest.main()
