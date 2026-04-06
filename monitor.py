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

HTTP endpoints (served on the same port as WebSocket):
    GET /health      200 OK — reachability probe
    GET /status      JSON — current phase, packet count, progress, config
    GET /apply?...   Apply new config and restart the pipeline
                     Params: iface, fm_grace, ad_grace, max_ae, alert_threshold, notify_url

Requires CAP_NET_RAW (or root) to capture live packets.

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
import time
import urllib.parse
import urllib.request
import urllib.error
from http import HTTPStatus

import numpy as np
from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ARP, ICMP
import websockets

from netStat import netStat as NetStat
from KitNET.KitNET import KitNET


# ─── Shared mutable state ────────────────────────────────────────────────────
_lock = threading.Lock()
_phase = 'stopped'          # 'FM' | 'AD' | 'exec' | 'stopped'
_pkt_count = 0
_last_rmse: float | None = None
_config: dict = {}

_clients: set = set()
_ws_loop: asyncio.AbstractEventLoop | None = None
_sniffer: AsyncSniffer | None = None
_sniffer_lock = threading.Lock()


# ─── Packet parsing ──────────────────────────────────────────────────────────

def _parse_packet(pkt, nstat):
    """Extract a KitNET feature vector from a live scapy packet."""
    IPtype = np.nan
    timestamp = float(pkt.time)
    framelen = len(pkt)
    srcIP = dstIP = srcproto = dstproto = ''

    if pkt.haslayer(IP):
        srcIP = pkt[IP].src; dstIP = pkt[IP].dst; IPtype = 0
    elif pkt.haslayer(IPv6):
        srcIP = pkt[IPv6].src; dstIP = pkt[IPv6].dst; IPtype = 1

    if pkt.haslayer(TCP):
        srcproto = str(pkt[TCP].sport); dstproto = str(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        srcproto = str(pkt[UDP].sport); dstproto = str(pkt[UDP].dport)

    srcMAC = pkt.src if hasattr(pkt, 'src') else ''
    dstMAC = pkt.dst if hasattr(pkt, 'dst') else ''

    if srcproto == '':
        if pkt.haslayer(ARP):
            srcproto = dstproto = 'arp'
            srcIP = pkt[ARP].psrc; dstIP = pkt[ARP].pdst; IPtype = 0
        elif pkt.haslayer(ICMP):
            srcproto = dstproto = 'icmp'; IPtype = 0
        elif srcIP + dstIP == '':
            srcIP = srcMAC; dstIP = dstMAC

    try:
        return nstat.updateGetStats(
            IPtype, srcMAC, dstMAC, srcIP, srcproto,
            dstIP, dstproto, int(framelen), timestamp,
        )
    except Exception as e:
        print(f"[warn] feature extraction failed: {e}", file=sys.stderr)
        return None


# ─── Alert helper ────────────────────────────────────────────────────────────

def _post_alert(notify_url, payload):
    """Fire-and-forget HTTP POST of an alert payload."""
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


# ─── Sniffer lifecycle ───────────────────────────────────────────────────────

def _make_on_packet(kitnet, nstat, cfg):
    """Return an on_packet callback bound to the given model instances."""
    global _phase, _pkt_count, _last_rmse

    fm = cfg['fm_grace']
    ad = cfg['ad_grace']
    threshold = cfg['alert_threshold']
    notify_url = cfg.get('notify_url', '')

    def on_packet(pkt):
        global _phase, _pkt_count, _last_rmse

        x = _parse_packet(pkt, nstat)
        if x is None or len(x) == 0:
            return

        rmse = kitnet.process(x)

        with _lock:
            _pkt_count += 1
            pc = _pkt_count
            if pc <= fm:
                _phase = 'FM'
                rmse_out = None
            elif pc <= fm + ad:
                _phase = 'AD'
                rmse_out = None
            else:
                _phase = 'exec'
                rmse_out = float(rmse)
                _last_rmse = rmse_out

        payload = {'n': pc, 'rmse': rmse_out, 'phase': _phase, 'ts': float(pkt.time)}
        print(json.dumps(payload), flush=True)

        # Broadcast to WebSocket clients
        if _clients and _ws_loop:
            msg = json.dumps(payload)
            asyncio.run_coroutine_threadsafe(
                asyncio.gather(
                    *[c.send(msg) for c in set(_clients)],
                    return_exceptions=True,
                ),
                _ws_loop,
            )

        # Threshold alert — exec phase only
        if _phase == 'exec' and rmse_out is not None and rmse_out >= threshold and notify_url:
            alert = {'source': 'kitsune', 'n': pc, 'rmse': rmse_out, 'ts': float(pkt.time)}
            threading.Thread(target=_post_alert, args=(notify_url, alert), daemon=True).start()

    return on_packet


def _apply_config(cfg: dict):
    """Stop any running sniffer, reinitialise the model, and start fresh."""
    global _sniffer, _phase, _pkt_count, _last_rmse, _config

    with _sniffer_lock:
        if _sniffer is not None:
            try:
                _sniffer.stop()
            except Exception:
                pass
            _sniffer = None

        with _lock:
            _pkt_count = 0
            _last_rmse = None
            _phase = 'FM'
            _config = dict(cfg)

        nstat = NetStat(np.nan, HostLimit=100_000_000_000, HostSimplexLimit=100_000_000_000)
        num_features = len(nstat.getNetStatHeaders())
        print(f"[init] feature vector size: {num_features}", flush=True)

        kitnet = KitNET(num_features, cfg['max_ae'], cfg['fm_grace'], cfg['ad_grace'])
        on_packet = _make_on_packet(kitnet, nstat, cfg)

        try:
            new_sniffer = AsyncSniffer(iface=cfg['iface'], prn=on_packet, store=False)
            new_sniffer.start()
            _sniffer = new_sniffer
            print(
                f"[sniffer] started on '{cfg['iface']}' "
                f"fm_grace={cfg['fm_grace']} ad_grace={cfg['ad_grace']} max_ae={cfg['max_ae']}",
                flush=True,
            )
        except PermissionError:
            print("[error] Permission denied — run with CAP_NET_RAW or as root.", file=sys.stderr)
            with _lock:
                _phase = 'stopped'
        except Exception as e:
            print(f"[error] sniffer start failed: {e}", file=sys.stderr)
            with _lock:
                _phase = 'stopped'


# ─── Status helper ───────────────────────────────────────────────────────────

def _get_status() -> dict:
    with _lock:
        cfg = dict(_config)
        phase = _phase
        pc = _pkt_count
        last_rmse = _last_rmse

    fm = cfg.get('fm_grace', 5000)
    ad = cfg.get('ad_grace', 50000)

    if phase == 'FM':
        fm_progress = min(1.0, pc / fm) if fm > 0 else 0.0
        ad_progress = 0.0
    elif phase == 'AD':
        fm_progress = 1.0
        ad_progress = min(1.0, (pc - fm) / ad) if ad > 0 else 0.0
    elif phase == 'exec':
        fm_progress = 1.0
        ad_progress = 1.0
    else:
        fm_progress = 0.0
        ad_progress = 0.0

    return {
        'phase': phase,
        'packet_count': pc,
        'running': _sniffer is not None,
        'last_rmse': last_rmse,
        'fm_progress': fm_progress,
        'ad_progress': ad_progress,
        'config': cfg,
    }


# ─── WebSocket / HTTP server ──────────────────────────────────────────────────

def _run_ws_server(loop: asyncio.AbstractEventLoop, port: int):
    global _ws_loop
    asyncio.set_event_loop(loop)
    _ws_loop = loop

    async def handler(ws):
        _clients.add(ws)
        try:
            await ws.wait_closed()
        finally:
            _clients.discard(ws)

    async def process_request(connection, request):
        # Let genuine WebSocket upgrade requests through
        if request.headers.get('Upgrade', '').lower() == 'websocket':
            return None

        parsed = urllib.parse.urlparse(request.path)
        path = parsed.path.rstrip('/')
        params = dict(urllib.parse.parse_qsl(parsed.query))

        if path in ('', '/health'):
            return connection.respond(HTTPStatus.OK, 'kitsune ok\n')

        if path == '/status':
            body = json.dumps(_get_status())
            return connection.respond(HTTPStatus.OK, body)

        if path == '/config':
            body = json.dumps(_get_status()['config'])
            return connection.respond(HTTPStatus.OK, body)

        if path == '/apply':
            current = _get_status()['config']
            try:
                new_cfg = {
                    'iface':           params.get('iface', current.get('iface', 'eth0')),
                    'fm_grace':        int(params.get('fm_grace',        current.get('fm_grace',        5000))),
                    'ad_grace':        int(params.get('ad_grace',        current.get('ad_grace',        50000))),
                    'max_ae':          int(params.get('max_ae',          current.get('max_ae',          10))),
                    'alert_threshold': float(params.get('alert_threshold', current.get('alert_threshold', 0.5))),
                    'notify_url':      params.get('notify_url',          current.get('notify_url',      '')),
                }
            except (ValueError, TypeError) as exc:
                return connection.respond(HTTPStatus.BAD_REQUEST, f'bad params: {exc}\n')

            # Restart sniffer in a background thread — don't block the event loop
            threading.Thread(target=_apply_config, args=(new_cfg,), daemon=True).start()
            body = json.dumps({'status': 'ok', 'config': new_cfg})
            return connection.respond(HTTPStatus.OK, body)

        return connection.respond(HTTPStatus.NOT_FOUND, 'not found\n')

    async def serve():
        async with websockets.serve(handler, '0.0.0.0', port,
                                    process_request=process_request):
            print(f"[ws] listening on ws://0.0.0.0:{port}", flush=True)
            await asyncio.Future()  # run forever

    loop.run_until_complete(serve())


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Kitsune live network anomaly monitor',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--iface',            default=os.environ.get('KITSUNE_IFACE', 'eth0'))
    parser.add_argument('--port',      type=int,   default=int(os.environ.get('KITSUNE_WS_PORT', '8765')))
    parser.add_argument('--fm-grace',  type=int,   default=int(os.environ.get('KITSUNE_FM_GRACE', '5000')))
    parser.add_argument('--ad-grace',  type=int,   default=int(os.environ.get('KITSUNE_AD_GRACE', '50000')))
    parser.add_argument('--max-ae',    type=int,   default=int(os.environ.get('KITSUNE_MAX_AE', '10')))
    parser.add_argument('--alert-threshold', type=float,
                        default=float(os.environ.get('KITSUNE_ALERT_THRESHOLD', '0.5')))
    parser.add_argument('--notify-url', default=os.environ.get('KITSUNE_NOTIFY_URL', ''))
    args = parser.parse_args()

    initial_cfg = {
        'iface':           args.iface,
        'fm_grace':        args.fm_grace,
        'ad_grace':        args.ad_grace,
        'max_ae':          args.max_ae,
        'alert_threshold': args.alert_threshold,
        'notify_url':      args.notify_url,
    }

    print(f"[init] fm_grace={args.fm_grace} | ad_grace={args.ad_grace} | max_ae={args.max_ae}", flush=True)
    if args.notify_url:
        print(f"[init] alert_threshold={args.alert_threshold} | notify_url={args.notify_url}", flush=True)

    # WebSocket / HTTP server in a dedicated thread
    ws_loop = asyncio.new_event_loop()
    ws_thread = threading.Thread(
        target=_run_ws_server, args=(ws_loop, args.port), daemon=True,
    )
    ws_thread.start()

    # Start the initial sniffing pipeline
    _apply_config(initial_cfg)

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n[stop] Interrupted by user.')
        sys.exit(0)


if __name__ == '__main__':
    main()
