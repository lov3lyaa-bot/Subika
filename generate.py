#!/usr/bin/env python3
"""
generate.py — Тянет VLESS-ссылки с GitHub, пингует, генерирует xray JSON-подписку
с burstObservatory + balancer для автовыбора лучшего сервера.

Usage: python3 generate.py
Output: docs/sub.json (xray full config) + docs/sub.txt (plain vless:// list)
"""

import json
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ============ CONFIG ============
SOURCE_URL = "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt"
PING_TIMEOUT_SEC = 2.5
PING_WORKERS = 50          # одновременных TCP-пингов
MAX_SERVERS = 80           # сколько лучших серверов попадёт в финальный конфиг
OUTPUT_DIR = Path("docs")

# ============ PARSE VLESS ============
def parse_vless(line: str) -> dict | None:
    """
    vless://uuid@host:port?security=reality&pbk=...&fp=...&sni=...&sid=...&type=tcp&flow=...#remark
    -> dict with outbound config
    """
    line = line.strip()
    if not line.startswith("vless://"):
        return None
    try:
        # vless://USER@HOST:PORT?QUERY#FRAGMENT
        body = line[len("vless://"):]
        if "#" in body:
            body, fragment = body.split("#", 1)
            remark = urllib.parse.unquote(fragment)
        else:
            remark = "VLESS"
        userinfo, hostpart = body.split("@", 1)
        uuid = userinfo
        if "?" in hostpart:
            hostport, query = hostpart.split("?", 1)
        else:
            hostport, query = hostpart, ""
        host, port = hostport.rsplit(":", 1)
        port = int(port)
        params = dict(urllib.parse.parse_qsl(query))
        return {
            "remark": remark,
            "host": host,
            "port": port,
            "uuid": uuid,
            "security": params.get("security", "none"),
            "encryption": params.get("encryption", "none"),
            "flow": params.get("flow", ""),
            "type": params.get("type", "tcp"),
            "sni": params.get("sni", ""),
            "pbk": params.get("pbk", ""),
            "fp": params.get("fp", "chrome"),
            "sid": params.get("sid", ""),
            "spx": params.get("spx", ""),
            "raw": line,
        }
    except Exception as e:
        print(f"  ! parse fail: {line[:60]}... -> {e}", file=sys.stderr)
        return None


# ============ FETCH SOURCE ============
def fetch_source() -> list[str]:
    print(f"→ fetch {SOURCE_URL}")
    req = urllib.request.Request(
        SOURCE_URL,
        headers={"User-Agent": "Mozilla/5.0 vpn-sub-generator"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        data = r.read().decode("utf-8", errors="ignore")
    lines = [l.strip() for l in data.splitlines() if l.strip().startswith("vless://")]
    print(f"  got {len(lines)} vless lines")
    return lines


# ============ TCP PING ============
def tcp_ping(host: str, port: int, timeout: float = PING_TIMEOUT_SEC) -> float | None:
    """Returns latency in ms, or None if unreachable."""
    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return (time.perf_counter() - start) * 1000
    except (socket.timeout, OSError):
        return None


def ping_all(servers: list[dict]) -> list[dict]:
    print(f"→ pinging {len(servers)} servers (workers={PING_WORKERS}, timeout={PING_TIMEOUT_SEC}s)")
    alive = []
    dead_count = 0
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        future_to_srv = {
            ex.submit(tcp_ping, s["host"], s["port"]): s for s in servers
        }
        for fut in as_completed(future_to_srv):
            srv = future_to_srv[fut]
            latency = fut.result()
            if latency is not None:
                srv["latency"] = round(latency, 1)
                alive.append(srv)
            else:
                dead_count += 1
    print(f"  alive: {len(alive)} · dead: {dead_count}")
    alive.sort(key=lambda s: s["latency"])
    return alive


# ============ BUILD XRAY OUTBOUND ============
def build_outbound(srv: dict) -> dict:
    tag = srv["remark"]
    stream = {"network": srv["type"] or "tcp"}

    if srv["security"] == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "fingerprint": srv["fp"] or "chrome",
            "publicKey": srv["pbk"],
            "serverName": srv["sni"],
        }
        if srv["sid"]:
            stream["realitySettings"]["shortId"] = srv["sid"]
        if srv["spx"]:
            stream["realitySettings"]["spiderX"] = srv["spx"]
    elif srv["security"] == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "fingerprint": srv["fp"] or "chrome",
            "serverName": srv["sni"] or srv["host"],
            "allowInsecure": False,
        }
    else:
        stream["security"] = "none"

    if srv["type"] == "tcp":
        stream["tcpSettings"] = {}

    user_obj = {
        "encryption": srv["encryption"] or "none",
        "id": srv["uuid"],
    }
    if srv["flow"]:
        user_obj["flow"] = srv["flow"]

    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": srv["host"],
                "port": srv["port"],
                "users": [user_obj],
            }]
        },
        "streamSettings": stream,
        "tag": tag,
    }


# ============ BUILD FULL CONFIG ============
def build_xray_config(servers: list[dict]) -> dict:
    selector = [s["remark"] for s in servers]
    outbounds = [build_outbound(s) for s in servers]
    outbounds.append({"protocol": "freedom", "tag": "direct"})
    outbounds.append({"protocol": "blackhole", "tag": "block"})

    return {
        "remarks": "🎪 DatlnVpn — Билет в Цыганестан",
        "log": {"loglevel": "warning", "dnsLog": False},
        "dns": {
            "queryStrategy": "UseIP",
            "servers": ["1.1.1.1", "1.0.0.1", "8.8.8.8"],
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "destOverride": ["http", "tls", "quic"],
                    "enabled": True,
                    "routeOnly": False,
                },
                "tag": "socks",
            },
            {
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {"allowTransparent": False},
                "sniffing": {
                    "destOverride": ["http", "tls", "quic"],
                    "enabled": True,
                    "routeOnly": False,
                },
                "tag": "http",
            },
        ],
        "outbounds": outbounds,
        "burstObservatory": {
            "pingConfig": {
                "destination": "https://www.gstatic.com/generate_204",
                "httpMethod": "GET",
                "interval": "3m",
                "sampling": 3,
                "timeout": "2s",
            },
            "subjectSelector": selector,
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "balancers": [
                {
                    "tag": "auto-balancer",
                    "selector": selector,
                    "strategy": {
                        "type": "leastLoad",
                        "settings": {
                            "baselines": ["1s"],
                            "expected": 1,
                            "tolerance": 0.8,
                        },
                    },
                }
            ],
            "rules": [
                {
                    "type": "field",
                    "network": "udp",
                    "port": "443",
                    "outboundTag": "block",
                },
                {
                    "type": "field",
                    "protocol": ["bittorrent"],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "domain": [
                        "localhost", "*.local", "*.localdomain",
                        "*.lan", "*.internal",
                    ],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "ip": [
                        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
                        "192.168.0.0/16", "169.254.0.0/16",
                        "::1/128", "fc00::/7", "fe80::/10",
                    ],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "auto-balancer",
                },
            ],
        },
    }


# ============ BUILD plain vless:// list (Base64) ============
def build_plain_subscription(servers: list[dict]) -> str:
    """Plain vless:// list, one per line. Some clients want Base64-encoded."""
    return "\n".join(s["raw"] for s in servers)


# ============ MAIN ============
def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    raw_lines = fetch_source()
    parsed = [p for p in (parse_vless(l) for l in raw_lines) if p]
    print(f"→ parsed {len(parsed)} valid VLESS configs")

    if not parsed:
        print("! no servers parsed, aborting", file=sys.stderr)
        sys.exit(1)

    alive = ping_all(parsed)
    if not alive:
        print("! all servers unreachable, fallback to top-N of parsed", file=sys.stderr)
        alive = parsed[:MAX_SERVERS]
    else:
        alive = alive[:MAX_SERVERS]

    config = build_xray_config(alive)

    sub_json_path = OUTPUT_DIR / "sub.json"
    sub_json_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"✓ wrote {sub_json_path} ({sub_json_path.stat().st_size // 1024} KB)")

    plain_text = build_plain_subscription(alive)
    sub_txt_path = OUTPUT_DIR / "sub.txt"
    sub_txt_path.write_text(plain_text, encoding="utf-8")
    print(f"✓ wrote {sub_txt_path}")

    import base64
    b64 = base64.b64encode(plain_text.encode("utf-8")).decode("ascii")
    sub_b64_path = OUTPUT_DIR / "sub"
    sub_b64_path.write_text(b64, encoding="utf-8")
    print(f"✓ wrote {sub_b64_path} (base64)")

    stats = {
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "source_url": SOURCE_URL,
        "total_parsed": len(parsed),
        "alive": len(alive),
        "best_latency_ms": alive[0].get("latency", "n/a") if alive else "n/a",
        "median_latency_ms": alive[len(alive)//2].get("latency", "n/a") if alive else "n/a",
    }
    (OUTPUT_DIR / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(f"✓ wrote {OUTPUT_DIR / 'stats.json'}")
    print(f"\n  best latency: {stats['best_latency_ms']} ms")
    print(f"  median:       {stats['median_latency_ms']} ms")


if __name__ == "__main__":
    main()
