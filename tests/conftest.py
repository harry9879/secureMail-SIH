import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from securemailscope import samples  # noqa: E402
from securemailscope.models import Flow, StreamStats  # noqa: E402


@pytest.fixture(scope="session")
def sample_paths(tmp_path_factory):
    """Generate the demo captures once per test run."""
    return samples.generate(str(tmp_path_factory.mktemp("samples")))


@pytest.fixture(scope="session")
def pki():
    return samples.build_pki()


def make_flow(client_bytes: bytes, server_bytes: bytes, port: int = 25, client=("10.0.0.5", 50000),
              server_ip: str = "203.0.113.9") -> Flow:
    return Flow(client=client, server=(server_ip, port), client_bytes=client_bytes, server_bytes=server_bytes,
                start_ts=samples.DEMO_T0, end_ts=samples.DEMO_T0 + 1, handshake_seen=True,
                client_stats=StreamStats(), server_stats=StreamStats(), client_role_reason="SYN without ACK")
