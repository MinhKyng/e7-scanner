#!/usr/bin/env python3
import argparse
import json
import time
from datetime import datetime, timezone
from collections import deque

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.config import conf
from scapy.sendrecv import sniff

def list_ifaces():
    for i, iface in enumerate(list(conf.ifaces.data.values())):
        name = getattr(iface, "name", str(iface))
        desc = getattr(iface, "description", "")
        print(f"[{i}] {name} {('- ' + desc) if desc else ''}")

def run_scan(duration_sec: int, bpf_filter: str, iface: str | None, max_chunks: int):
    chunks = deque(maxlen=max_chunks)

    def on_packet(pkt):
        if IP in pkt and TCP in pkt and Raw in pkt and pkt[Raw].load:
            payload = bytes(pkt[Raw].load)
            chunks.append(payload.hex())

    sniff(
        iface=iface,
        prn=on_packet,
        store=False,
        filter=bpf_filter,
        timeout=duration_sec,
    )

    return list(chunks)

def main():
    p = argparse.ArgumentParser(description="Standalone packet payload collector (writes payloads as hex).")
    p.add_argument("--duration", type=int, default=30, help="Seconds to sniff (default: 30)")
    p.add_argument("--out", default="scan.json", help="Output JSON file (default: scan.json)")
    p.add_argument("--iface", default=None, help="Interface name to sniff (default: scapy default/all)")
    p.add_argument("--filter", default="tcp", help="BPF filter (default: tcp)")
    p.add_argument("--max-chunks", type=int, default=5000, help="Max payload chunks to keep (default: 5000)")
    p.add_argument("--list-ifaces", action="store_true", help="List capture interfaces and exit")

    args = p.parse_args()

    if args.list_ifaces:
        list_ifaces()
        return

    started = datetime.now(timezone.utc).isoformat()

    chunks_hex = run_scan(
        duration_sec=args.duration,
        bpf_filter=args.filter,
        iface=args.iface,
        max_chunks=args.max_chunks,
    )

    out_obj = {
        "version": 1,
        "captured_at": started,
        "duration_sec": args.duration,
        "filter": args.filter,
        "iface": args.iface,
        "chunks_hex": chunks_hex,
        "chunks_count": len(chunks_hex),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=2)

    print(f"Wrote {len(chunks_hex)} chunks to {args.out}")

if __name__ == "__main__":
    main()
