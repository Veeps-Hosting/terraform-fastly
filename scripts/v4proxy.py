#!/usr/bin/env python3
"""Minimal HTTP CONNECT proxy that only dials IPv4.

Some provider API tokens are IP-allowlisted to a single IPv4 address, and Go's HTTP client
prefers IPv6 when the host has it, and Cloudflare rejects the token from that address. Run this on 127.0.0.1 and point
HTTPS_PROXY at it for the duration of a plan/apply; see scripts/tg-cf.

Stop-gap for an IPv4-only token allowlist.
"""
import asyncio
import socket
import sys


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def handle(client_reader, client_writer):
    try:
        request = await client_reader.readuntil(b"\r\n\r\n")
        method, target, _ = request.split(b"\r\n", 1)[0].decode().split(" ", 2)
        if method != "CONNECT":
            client_writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return client_writer.close()
        host, port = target.rsplit(":", 1)
        up_reader, up_writer = await asyncio.open_connection(host, int(port), family=socket.AF_INET)
    except Exception:
        client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        return client_writer.close()
    client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await client_writer.drain()
    await asyncio.gather(pipe(client_reader, up_writer), pipe(up_reader, client_writer))


async def main(port):
    server = await asyncio.start_server(handle, "127.0.0.1", port)
    print(f"v4proxy listening on 127.0.0.1:{server.sockets[0].getsockname()[1]}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 0))
