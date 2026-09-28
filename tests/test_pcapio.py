"""Stage 00-01: container formats, link types, layer walk."""
import struct

import pytest

from securemailscope import samples
from securemailscope.pcapio import PcapError, read_packets


def _one_segment(src="10.0.0.1", dst="10.0.0.2", payload=b"220 hello\r\n"):
    seg = samples.tcp_segment(src, dst, 25, 40000, 1000, 2000, 0x18, payload)
    return samples.ip_packet(src, dst, 6, seg)


def _write_raw_pcap(path, linktype, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for fr in frames:
            f.write(struct.pack("<IIII", 1, 0, len(fr), len(fr)) + fr)


def test_pcap_ethernet_roundtrip(tmp_path):
    cap = samples.Capture()
    cap.add(100.5, _one_segment())
    p = tmp_path / "a.pcap"
    cap.write_pcap(str(p))
    pkts, st = read_packets(str(p))
    assert st.format == "pcap" and st.link_types == {1}
    assert len(pkts) == 1
    k = pkts[0]
    assert (k.src, k.sport, k.dst, k.dport) == ("10.0.0.1", 25, "10.0.0.2", 40000)
    assert k.payload == b"220 hello\r\n" and k.seq == 1000
    assert abs(k.ts - 100.5) < 1e-6


def test_pcapng_linux_sll_nanosecond(tmp_path):
    cap = samples.Capture()
    cap.add(1234.000000123, _one_segment())
    p = tmp_path / "a.pcapng"
    cap.write_pcapng(str(p), linktype=113)
    pkts, st = read_packets(str(p))
    assert st.format == "pcapng" and st.link_types == {113}
    assert pkts[0].payload == b"220 hello\r\n"
    assert abs(pkts[0].ts - 1234.000000123) < 1e-6


def test_stacked_vlan_tags_are_walked(tmp_path):
    ip = _one_segment()
    macs = b"\x02" * 12
    qinq = macs + struct.pack("!HH", 0x88A8, 10) + struct.pack("!HH", 0x8100, 20) + struct.pack("!H", 0x0800) + ip
    p = tmp_path / "q.pcap"
    _write_raw_pcap(str(p), 1, [qinq])
    pkts, _ = read_packets(str(p))
    assert len(pkts) == 1 and pkts[0].payload == b"220 hello\r\n"


@pytest.mark.parametrize("linktype,prefix", [(0, struct.pack("<I", 2)), (101, b""), (228, b"")])
def test_null_and_raw_link_types(tmp_path, linktype, prefix):
    p = tmp_path / f"l{linktype}.pcap"
    _write_raw_pcap(str(p), linktype, [prefix + _one_segment()])
    pkts, st = read_packets(str(p))
    assert len(pkts) == 1 and st.link_types == {linktype}


def test_ipv6_with_extension_header(tmp_path):
    src, dst = "2001:db8::1", "2001:db8::2"
    seg = samples.tcp_segment(src, dst, 143, 50000, 1, 1, 0x18, b"* OK\r\n")
    hop_by_hop = bytes([6, 0]) + b"\x00" * 6          # next header TCP, length 0 (8 bytes)
    ip6 = struct.pack("!IHBB", 6 << 28, len(hop_by_hop) + len(seg), 0, 64) + \
        samples._ip_bytes(src) + samples._ip_bytes(dst) + hop_by_hop + seg
    p = tmp_path / "v6.pcap"
    _write_raw_pcap(str(p), 101, [ip6])
    pkts, _ = read_packets(str(p))
    assert pkts[0].src == src and pkts[0].payload == b"* OK\r\n"


def test_fragments_and_non_tcp_are_counted_not_parsed(tmp_path):
    frag = samples.ip_packet("10.0.0.1", "10.0.0.2", 6, b"\x00" * 40, frag_flags=0x2000)
    udp = samples.ip_packet("10.0.0.1", "10.0.0.2", 17, b"\x00" * 16)
    p = tmp_path / "f.pcap"
    _write_raw_pcap(str(p), 101, [frag, udp, _one_segment()])
    pkts, st = read_packets(str(p))
    assert len(pkts) == 1 and st.fragments_skipped == 1 and st.non_tcp == 1


def test_bad_magic_raises(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"GIF89a" + b"\x00" * 30)
    with pytest.raises(PcapError):
        read_packets(str(p))
