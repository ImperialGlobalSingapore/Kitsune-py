#!/usr/bin/env python3
"""
Kitsune live network monitor.

Sniffs packets from a network interface, runs them through KitNET, and
broadcasts RMSE anomaly scores as JSON over a WebSocket and stdout.
Optionally POSTs threshold-crossing alerts to a notify URL (e.g. C2 dashboard).

Configuration (CLI args override env vars):
    --iface          / KITSUNE_IFACE          Network interface to sniff (default: eth0)
    --port           / KITSUNE_WS_PORT        WebSocket port (default: 8765)
    --fm-grace       / KITSUNE_FM_GRACE       Feature-mapping grace period in packets (default: 5000)
    --ad-grace       / KITSUNE_AD_GRACE       Anomaly-detector grace period in packets (default: 50000)
    --max-ae         / KITSUNE_MAX_AE         Max features per autoencoder (default: 10)
    --alert-threshold/ KITSUNE_ALERT_THRESHOLD RMSE threshold for triggering alerts (default: 0.5)
    --notify-url     / KITSUNE_NOTIFY_URL     HTTP endpoint to POST alerts to (default: disabled)

Requires CAP_NET_RAW (or root) to capture live packets.

Docker example:
    docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \\
        -e KITSUNE_IFACE=eth0 -p 8765:8765 kitsune-py

WebSocket message format:
    {"n": 1234, "rmse": 0.042, "phase": "exec", "ts": 1712345678.9}
    phase is one of: "FM" (feature mapping), "AD" (AE training), "exec" (live scoring)
    rmse is null during FM and AD phases.

Alert POST body (sent to KITSUNE_NOTIFY_URL on threshold breach):
    {"source": "kitsune", "n": 1234, "rmse": 0.91, "ts": 1712345678.9}
"""

import argparse
import asyncio
import json
import os
import sys
import threading
import urllib.request
import urllib.error

import numpy as np
from scapy.all import sniff, IP, IPv6, TCP, UDP, ARP, ICMP
import websockets

from netStat import netStat as NetStat
from KitNET.KitNET import KitNET


def _parse_packet(pkt, nstat):
    """Extract a KitNET feature vector from a live scapy packet.
    Returns None if the packet could not be parsed."""
    IPtype = np.nan
    timestamp = float(pkt.time)
    framelen = len(pkt)
    srcIP = dstIP = srcproto = dstproto = ''

    if pkt.haslayer(IP):
        srcIP = pkt[IP].src
        dstIP = pkt[IP].dst
        IPtype = 0
    elif pkt.haslayer(IPv6):
        srcIP = pkt[IPv6].src
        dstIP = pkt[IPv6].dst
        IPtype = 1

    if pkt.haslayer(TCP):
        srcproto = str(pkt[TCP].sport)
        dstproto = str(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        srcproto = str(pkt[UDP].sport)
        dstproto = str(pkt[UDP].dport)

    srcMAC = pkt.src if hasattr(pkt, 'src') else ''
    dstMAC = pkt.dst if hasattr(pkt, 'dst') else ''

    if srcproto == '':
        if pkt.haslayer(ARP):
            srcproto = dstproto = 'arp'
            srcIP = pkt[ARP].psrc
            dstIP = pkt[ARP].pdst
            IPtype = 0
        elif pkt.haslayer(ICMP):
            srcproto = dstproto = 'icmp'
            IPtype = 0
        elif srcIP + dstIP == '':
            srcIP = srcMAC
            dstIP = dstMAC

    try:
        return nstat.updateGetStats(
            IPtype, srcMAC, dstMAC, srcIP, srcproto,
            dstIP, dstproto, int(framelen), timestamp
        )
    except Exception as e:
        print(f"[warn] feature extraction failed: {e}", file=sys.stderr)
        return None


def _run_ws_server(loop, clients, port):
    """Blocking: starts the WebSocket server in the given event loop."""
    asyncio.set_event_loop(loop)

    async def handler(ws):
        clients.add(ws)
        try:
            await ws.wait_closed()
        finally:
            clients.discard(ws)

    async def serve():
        async with websockets.serve(handler, '0.0.0.0', port):
            print(f"[ws] listening on ws://0.0.0.0:{port}")
            await asyncio.Future()  # run forever

    loop.run_until_complete(serve())


def _post_alert(notify_url, payload):
    """Fire-and-forget HTTP POST of an alert payload. Errors are logged, not raised."""
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            notify_url, data=data,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=2):
            pass
    except urllib.error.URLError as e:
        print(f"[warn] alert POST failed: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Kitsune live network anomaly monitor',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--iface',           default=os.environ.get('KITSUNE_IFACE', 'eth0'))
    parser.add_argument('--port',      type=int,   default=int(os.environ.get('KITSUNE_WS_PORT', '8765')))
    parser.add_argument('--fm-grace',  type=int,   default=int(os.environ.get('KITSUNE_FM_GRACE', '5000')))
    parser.add_argument('--ad-grace',  type=int,   default=int(os.environ.get('KITSUNE_AD_GRACE', '50000')))
    parser.add_argument('--max-ae',    type=int,   default=int(os.environ.get('KITSUNE_MAX_AE', '10')))
    parser.add_argument('--alert-threshold', type=float,
                        default=float(os.environ.get('KITSUNE_ALERT_THRESHOLD', '0.5')))
    parser.add_argument('--notify-url', default=os.environ.get('KITSUNE_NOTIFY_URL', ''))
    args = parser.parse_args()

    # Initialise the AfterImage statistics tracker and derive feature count
    nstat = NetStat(np.nan, maxHost=100_000_000_000, HostSimplexLimit=100_000_000_000)
    num_features = len(nstat.getNetStatHeaders())
    print(f"[init] feature vector size: {num_features}")

    kitnet = KitNET(num_features, args.max_ae, args.fm_grace, args.ad_grace)

    # WebSocket server in a dedicated background thread / event loop
    clients: set = set()
    ws_loop = asyncio.new_event_loop()
    ws_thread = threading.Thread(
        target=_run_ws_server, args=(ws_loop, clients, args.port), daemon=True
    )
    ws_thread.start()

    packet_count = 0

    def _broadcast(payload: dict):
        """Fire-and-forget send to all connected WebSocket clients."""
        if not clients:
            return
        msg = json.dumps(payload)
        snapshot = set(clients)
        asyncio.run_coroutine_threadsafe(
            asyncio.gather(*[c.send(msg) for c in snapshot], return_exceptions=True),
            ws_loop,
        )

    def on_packet(pkt):
        nonlocal packet_count

        x = _parse_packet(pkt, nstat)
        if x is None or len(x) == 0:
            return

        packet_count += 1
        rmse = kitnet.process(x)

        if packet_count <= args.fm_grace:
            phase = 'FM'
            rmse_out = None
        elif packet_count <= args.fm_grace + args.ad_grace:
            phase = 'AD'
            rmse_out = None
        else:
            phase = 'exec'
            rmse_out = float(rmse)

        payload = {
            'n':     packet_count,
            'rmse':  rmse_out,
            'phase': phase,
            'ts':    float(pkt.time),
        }

        print(json.dumps(payload), flush=True)
        _broadcast(payload)

        # Threshold alert — only during exec phase
        if phase == 'exec' and rmse_out is not None and rmse_out >= args.alert_threshold:
            alert = {'source': 'kitsune', 'n': packet_count, 'rmse': rmse_out, 'ts': float(pkt.time)}
            if args.notify_url:
                threading.Thread(target=_post_alert, args=(args.notify_url, alert), daemon=True).start()

    print(f"[init] sniffing on interface '{args.iface}'")
    print(f"[init] FM grace: {args.fm_grace} pkts  |  AD grace: {args.ad_grace} pkts")
    if args.notify_url:
        print(f"[init] alert threshold: {args.alert_threshold}  |  notify URL: {args.notify_url}")
    try:
        sniff(iface=args.iface, prn=on_packet, store=False)
    except PermissionError:
        print(
            "[error] Permission denied. Run with --cap-add NET_RAW (Docker) or as root.",
            file=sys.stderr,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[stop] Interrupted by user.")
        sys.exit(0)


if __name__ == '__main__':
    main()
