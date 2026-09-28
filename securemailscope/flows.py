"""Stage 02: group segments into conversations and reassemble each direction.

Correctness rules (see docs/03-capture-and-reassembly.md):
  * order by (seq - isn) mod 2**32, so wrap-around at 2**32 is harmless
  * drop pure retransmissions (segment entirely below the cursor)
  * trim partial overlaps, and count overlaps whose bytes disagree
  * the client is whoever sent SYN without ACK
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import Flow, Packet, StreamStats

MOD = 1 << 32
HALF = 1 << 31

# Ports only break ties when no handshake was captured; they never decide the protocol.
_WELL_KNOWN_SERVER_PORTS = {25, 465, 587, 2525, 143, 993, 110, 995, 24, 26}


def _canon(p: Packet) -> tuple:
    a, b = (p.src, p.sport), (p.dst, p.dport)
    return (a, b) if a <= b else (b, a)


def _rel(seq: int, base: int) -> int:
    """Signed distance from base in sequence space."""
    d = (seq - base) % MOD
    return d - MOD if d >= HALF else d


def reassemble(segments: list[Packet], isn: int | None) -> tuple[bytes, StreamStats]:
    """Rebuild one direction's byte stream from its data-bearing segments."""
    stats = StreamStats()
    data_segs = [s for s in segments if s.payload]
    stats.segments = len(data_segs)
    if not data_segs:
        return b"", stats

    if isn is not None:
        base = (isn + 1) % MOD                 # first data byte follows the SYN
    else:
        # capture began mid-stream: use the earliest seq in circular order
        base = data_segs[0].seq
        for s in data_segs:
            if _rel(s.seq, base) < 0:
                base = s.seq

    arrival = [(_rel(s.seq, base), i, s.payload) for i, s in enumerate(data_segs)]
    for prev, cur in zip(arrival, arrival[1:]):
        if cur[0] < prev[0]:
            stats.out_of_order += 1

    ordered = sorted((o, -len(p), i, p) for o, i, p in arrival if o >= 0)
    out = bytearray()
    cursor = 0
    for off, _neg_len, _i, payload in ordered:
        end = off + len(payload)
        if end <= cursor:
            # retransmission (or a fully-covered overlap); check it agrees with what we kept
            if bytes(out[off:end]) != payload:
                stats.overlap_conflicts += 1
            stats.retransmissions += 1
            continue
        if off > cursor:
            stats.gaps += 1
            out.extend(b"\x00" * (off - cursor))  # keep offsets stable; parsers see a hole
            cursor = off
        if off < cursor:
            overlap = cursor - off
            if bytes(out[off:cursor]) != payload[:overlap]:
                stats.overlap_conflicts += 1
            payload = payload[overlap:]
            stats.overlaps_trimmed += 1
        out.extend(payload)
        cursor += len(payload)
    stats.bytes = len(out)
    return bytes(out), stats


def build_flows(packets: Iterable[Packet]) -> list[Flow]:
    groups: dict[tuple, list[Packet]] = defaultdict(list)
    for p in packets:
        groups[_canon(p)].append(p)

    flows: list[Flow] = []
    for (a, b), pkts in groups.items():
        pkts.sort(key=lambda p: (p.ts, p.frame))
        # Split on a fresh SYN after FIN/RST (port reuse creates a new conversation)
        for conv in _split_conversations(pkts):
            flow = _make_flow(conv, a, b)
            if flow is not None:
                flows.append(flow)
    flows.sort(key=lambda f: f.start_ts)
    return flows


def _split_conversations(pkts: list[Packet]) -> list[list[Packet]]:
    convs: list[list[Packet]] = [[]]
    closed = False
    for p in pkts:
        if p.syn and not p.ack_flag and closed and convs[-1]:
            convs.append([])
            closed = False
        convs[-1].append(p)
        if p.fin or p.rst:
            closed = True
    return [c for c in convs if c]


def _make_flow(pkts: list[Packet], a: tuple, b: tuple) -> Flow | None:
    syn = next((p for p in pkts if p.syn and not p.ack_flag), None)
    synack = next((p for p in pkts if p.syn and p.ack_flag), None)
    if syn:
        client, server, reason = (syn.src, syn.sport), (syn.dst, syn.dport), "SYN without ACK"
    elif synack:
        server, client, reason = (synack.src, synack.sport), (synack.dst, synack.dport), "sender of SYN/ACK is server"
    else:
        # No handshake in the capture. Prefer the side on a well-known mail port,
        # then the lower port, and say so in the flow so analysts can discount it.
        if a[1] in _WELL_KNOWN_SERVER_PORTS and b[1] not in _WELL_KNOWN_SERVER_PORTS:
            server, client = a, b
        elif b[1] in _WELL_KNOWN_SERVER_PORTS and a[1] not in _WELL_KNOWN_SERVER_PORTS:
            server, client = b, a
        else:
            server, client = (a, b) if a[1] < b[1] else (b, a)
        reason = "no handshake captured; inferred from ports (low confidence)"

    c2s = [p for p in pkts if (p.src, p.sport) == client]
    s2c = [p for p in pkts if (p.src, p.sport) == server]
    c_isn = syn.seq if syn else None
    s_isn = synack.seq if synack else None
    c_bytes, c_stats = reassemble(c2s, c_isn)
    s_bytes, s_stats = reassemble(s2c, s_isn)
    if not c_bytes and not s_bytes:
        return None
    return Flow(
        client=client, server=server,
        client_bytes=c_bytes, server_bytes=s_bytes,
        start_ts=pkts[0].ts, end_ts=pkts[-1].ts,
        handshake_seen=bool(syn and synack),
        client_stats=c_stats, server_stats=s_stats,
        client_role_reason=reason, frames=len(pkts),
    )
