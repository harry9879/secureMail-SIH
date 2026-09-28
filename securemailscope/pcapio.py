"""Stage 00-01: read PCAP / PCAPNG and walk link -> IP -> TCP.

Hand-rolled with `struct`: no dependencies, runs on an air-gapped forensic box.

Supported link types:
    0   BSD null / loopback      (4-byte address family, host byte order)
    1   Ethernet                 (with stacked 802.1Q / 802.1ad VLAN tags)
    101 raw IP                   (also 228 = raw IPv4, 229 = raw IPv6)
    113 Linux cooked (SLL)       (also 276 = SLL2)
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator, Optional

from .models import Packet

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
ETH_IPV4, ETH_IPV6 = 0x0800, 0x86DD
IPV6_EXT_HEADERS = {0, 43, 60, 51, 135, 139, 140}  # hop-by-hop, routing, dest opts, AH, mobility, HIP, shim6
IPV6_FRAGMENT = 44
PROTO_TCP = 6


class PcapError(Exception):
    pass


@dataclass
class ReadStats:
    format: str = ""
    frames: int = 0
    tcp_segments: int = 0
    non_ip: int = 0
    non_tcp: int = 0
    fragments_skipped: int = 0
    truncated: int = 0
    link_types: set = field(default_factory=set)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["link_types"] = sorted(self.link_types)
        return d


# --------------------------------------------------------------------------- container formats

def _iter_pcap(f: BinaryIO, magic: bytes) -> Iterator[tuple[float, int, bytes]]:
    table = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }
    endian, resolution = table[magic]
    rest = f.read(20)
    if len(rest) < 20:
        raise PcapError("truncated pcap global header")
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", rest)
    linktype &= 0x0FFFFFFF  # upper bits carry FCS info
    rec = struct.Struct(endian + "IIII")
    while True:
        hdr = f.read(16)
        if len(hdr) < 16:
            return
        sec, frac, incl, _orig = rec.unpack(hdr)
        data = f.read(incl)
        if len(data) < incl:
            return
        yield sec + frac * resolution, linktype, data


def _iter_pcapng(f: BinaryIO, first: bytes) -> Iterator[tuple[float, int, bytes]]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds-per-tick)
    buf = first
    while True:
        if len(buf) < 8:
            buf += f.read(8 - len(buf))
            if len(buf) < 8:
                return
        btype_raw, blen_raw = buf[:4], buf[4:8]
        if btype_raw == b"\x0a\x0d\x0d\x0a":
            # Section header: byte-order magic decides endianness for the whole section
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", blen_raw)[0]
            f.read(blen - 12)
            interfaces = []
            buf = b""
            continue
        btype, blen = struct.unpack(endian + "II", buf[:8])
        if blen < 12:
            raise PcapError("corrupt pcapng block length")
        body = f.read(blen - 8)
        buf = b""
        if len(body) < blen - 8:
            return
        body = body[:-4]  # trailing block length
        if btype == 1:  # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            tick = 1e-6
            opts = body[8:]
            while len(opts) >= 4:
                code, olen = struct.unpack(endian + "HH", opts[:4])
                if code == 0:
                    break
                val = opts[4:4 + olen]
                if code == 9 and val:  # if_tsresol
                    v = val[0]
                    tick = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                opts = opts[4 + ((olen + 3) & ~3):]
            interfaces.append((linktype, tick))
        elif btype == 6:  # Enhanced Packet Block
            iface, ts_hi, ts_lo, incl, _orig = struct.unpack(endian + "IIIII", body[:20])
            linktype, tick = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6)
            yield ((ts_hi << 32) | ts_lo) * tick, linktype, body[20:20 + incl]
        elif btype == 3:  # Simple Packet Block (no timestamp)
            linktype = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            yield 0.0, linktype, body[4:]
        elif btype == 2:  # obsolete Packet Block
            iface, _drops, ts_hi, ts_lo, incl, _orig = struct.unpack(endian + "HHIIII", body[:20])
            linktype, tick = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1e-6)
            yield ((ts_hi << 32) | ts_lo) * tick, linktype, body[20:20 + incl]
        # other blocks (name resolution, statistics, custom) are skipped


def iter_frames(f: BinaryIO, stats: Optional[ReadStats] = None) -> Iterator[tuple[float, int, bytes]]:
    magic = f.read(4)
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        if stats: stats.format = "pcap"
        yield from _iter_pcap(f, magic)
    elif magic == b"\x0a\x0d\x0d\x0a":
        if stats: stats.format = "pcapng"
        yield from _iter_pcapng(f, magic + f.read(4))
    else:
        raise PcapError(f"not a pcap/pcapng file (magic {magic.hex()})")


# --------------------------------------------------------------------------- layer walk

def _link_to_ip(linktype: int, data: bytes) -> tuple[Optional[int], bytes]:
    """Return (ip_version, ip_packet) or (None, b'')."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None, b""
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        while etype in VLAN_ETHERTYPES:  # tags stack (QinQ), so loop
            if len(data) < off + 4:
                return None, b""
            etype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        payload = data[off:]
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None, b""
        etype = struct.unpack("!H", data[14:16])[0]
        payload = data[16:]
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None, b""
        etype = struct.unpack("!H", data[0:2])[0]
        payload = data[20:]
    elif linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None, b""
        fam_le = struct.unpack("<I", data[:4])[0]
        fam_be = struct.unpack(">I", data[:4])[0]
        fam = fam_le if fam_le < 256 else fam_be
        payload = data[4:]
        if fam == 2:
            return 4, payload
        if fam in (10, 24, 28, 30):  # AF_INET6 differs per OS
            return 6, payload
        return None, b""
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not data:
            return None, b""
        v = data[0] >> 4
        return (v, data) if v in (4, 6) else (None, b"")
    else:
        return None, b""
    if etype == ETH_IPV4:
        return 4, payload
    if etype == ETH_IPV6:
        return 6, payload
    return None, b""


def _ip_to_tcp(version: int, pkt: bytes, stats: ReadStats) -> Optional[tuple[str, str, bytes]]:
    if version == 4:
        if len(pkt) < 20:
            stats.truncated += 1
            return None
        ihl = (pkt[0] & 0x0F) * 4
        total_len = struct.unpack("!H", pkt[2:4])[0]
        flags_frag = struct.unpack("!H", pkt[6:8])[0]
        more_frags = flags_frag & 0x2000
        frag_off = flags_frag & 0x1FFF
        if frag_off or more_frags:
            # Non-first fragments carry no TCP header; first fragments carry a partial
            # segment. Reassembling IP fragments is out of scope, so skip and count.
            stats.fragments_skipped += 1
            return None
        if pkt[9] != PROTO_TCP:
            stats.non_tcp += 1
            return None
        end = total_len if 0 < total_len <= len(pkt) else len(pkt)
        src = str(ipaddress.IPv4Address(pkt[12:16]))
        dst = str(ipaddress.IPv4Address(pkt[16:20]))
        return src, dst, pkt[ihl:end]
    if version == 6:
        if len(pkt) < 40:
            stats.truncated += 1
            return None
        plen = struct.unpack("!H", pkt[4:6])[0]
        nxt = pkt[6]
        src = str(ipaddress.IPv6Address(pkt[8:24]))
        dst = str(ipaddress.IPv6Address(pkt[24:40]))
        body = pkt[40:40 + plen] if plen else pkt[40:]
        while nxt in IPV6_EXT_HEADERS or nxt == IPV6_FRAGMENT:
            if len(body) < 8:
                stats.truncated += 1
                return None
            if nxt == IPV6_FRAGMENT:
                stats.fragments_skipped += 1
                return None
            hdr_len = (body[1] + 2) * 4 if nxt == 51 else (body[1] + 1) * 8
            nxt, body = body[0], body[hdr_len:]
        if nxt != PROTO_TCP:
            stats.non_tcp += 1
            return None
        return src, dst, body
    return None


def read_packets(path: str, stats: Optional[ReadStats] = None) -> tuple[list[Packet], ReadStats]:
    stats = stats or ReadStats()
    packets: list[Packet] = []
    with open(path, "rb") as f:
        for ts, linktype, frame in iter_frames(f, stats):
            stats.frames += 1
            stats.link_types.add(linktype)
            version, ip = _link_to_ip(linktype, frame)
            if version is None:
                stats.non_ip += 1
                continue
            res = _ip_to_tcp(version, ip, stats)
            if res is None:
                continue
            src, dst, seg = res
            if len(seg) < 20:
                stats.truncated += 1
                continue
            sport, dport, seq, ack, off_flags = struct.unpack("!HHIIH", seg[:14])
            data_off = (off_flags >> 12) * 4
            flags = off_flags & 0x01FF
            if data_off < 20 or data_off > len(seg):
                stats.truncated += 1
                continue
            stats.tcp_segments += 1
            packets.append(Packet(stats.frames, ts, src, dst, sport, dport, seq, ack, flags, bytes(seg[data_off:])))
    return packets, stats
