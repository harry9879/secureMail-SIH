"""Stage 02: TCP reassembly - the hardest correctness problem in the build."""
from securemailscope.flows import build_flows, reassemble
from securemailscope.models import Packet


def seg(seq, data, src=("10.0.0.5", 50000), dst=("10.0.0.9", 25), flags=0x18, ts=0.0, frame=0):
    return Packet(frame, ts, src[0], dst[0], src[1], dst[1], seq % (1 << 32), 0, flags, data)


def test_in_order():
    out, st = reassemble([seg(101, b"hello "), seg(107, b"world")], isn=100)
    assert out == b"hello world" and st.retransmissions == 0


def test_out_of_order_is_reordered():
    out, st = reassemble([seg(107, b"world"), seg(101, b"hello ")], isn=100)
    assert out == b"hello world" and st.out_of_order == 1


def test_pure_retransmission_dropped():
    out, st = reassemble([seg(101, b"hello "), seg(107, b"world"), seg(101, b"hello ")], isn=100)
    assert out == b"hello world" and st.retransmissions == 1


def test_partial_overlap_trimmed():
    out, st = reassemble([seg(101, b"hello "), seg(104, b"lo world")], isn=100)
    assert out == b"hello world" and st.overlaps_trimmed == 1 and st.overlap_conflicts == 0


def test_conflicting_overlap_is_counted():
    # classic IDS-evasion: an overlapping segment carries different bytes
    out, st = reassemble([seg(101, b"hello "), seg(104, b"XX world")], isn=100)
    assert out == b"hello world"          # first-arrival wins
    assert st.overlap_conflicts == 1


def test_sequence_wraparound():
    isn = (1 << 32) - 4                       # data starts 3 bytes before the wrap
    out, _ = reassemble([seg(isn + 1, b"abc"), seg(0, b"def"), seg(3, b"ghi")], isn=isn)
    assert out == b"abcdefghi"


def test_gap_is_recorded_and_offsets_kept():
    out, st = reassemble([seg(101, b"ab"), seg(105, b"ef")], isn=100)
    assert st.gaps == 1 and out == b"ab\x00\x00ef"


def test_no_syn_uses_circular_minimum():
    out, _ = reassemble([seg(5, b"world"), seg((1 << 32) - 1, b"hello ")], isn=None)
    assert out.startswith(b"hello")


def test_client_is_syn_sender_even_on_high_port():
    c, s = ("10.0.0.5", 25000), ("10.0.0.9", 60000)
    pkts = [seg(99, b"", src=c, dst=s, flags=0x02, ts=0),
            Packet(1, 0.01, s[0], c[0], s[1], c[1], 499, 100, 0x12, b""),
            seg(100, b"EHLO x\r\n", src=c, dst=s, ts=0.03, frame=2),
            Packet(3, 0.02, s[0], c[0], s[1], c[1], 500, 100, 0x18, b"220 hi\r\n")]
    (flow,) = build_flows(pkts)
    assert flow.client == c and flow.server == s and flow.client_role_reason == "SYN without ACK"
    assert flow.client_bytes == b"EHLO x\r\n" and flow.server_bytes == b"220 hi\r\n"


def test_no_handshake_falls_back_to_mail_port():
    c, s = ("10.0.0.5", 51000), ("10.0.0.9", 587)
    pkts = [Packet(0, 0, s[0], c[0], s[1], c[1], 10, 0, 0x18, b"220 x\r\n"),
            seg(20, b"EHLO\r\n", src=c, dst=s, ts=0.1, frame=1)]
    (flow,) = build_flows(pkts)
    assert flow.server == s and "low confidence" in flow.client_role_reason
