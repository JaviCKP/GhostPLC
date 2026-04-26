import hashlib
import ipaddress
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from .storage import insert_events, read_recent_events
except ImportError:
    from storage import insert_events, read_recent_events

DEFAULT_DATA_DIR = Path.home() / "ghostplc-sensor" / "data"
DATA_DIR = Path(os.getenv("GHOSTPLC_DATA_DIR", str(DEFAULT_DATA_DIR))).expanduser()
EVENTS_FILE = Path(os.getenv("GHOSTPLC_EVENTS_FILE", str(DATA_DIR / "events.json"))).expanduser()
MAX_EVENTS = int(os.getenv("GHOSTPLC_MAX_EVENTS", "5000"))
LOG_WINDOW_SECONDS = int(os.getenv("GHOSTPLC_LOG_WINDOW_SECONDS", "90"))
EXPORT_EVENTS_JSON = os.getenv("GHOSTPLC_EXPORT_EVENTS_JSON", "0") == "1"

CONTAINERS = {
    "ghostplc-conpot": "ics",
    "ghostplc-cowrie": "ssh",
}

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOCKER_TS_REGEX = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+Z)\s+(?P<message>.*)$")

DEMO_GEO = [
    ("US", "United States", 37.7510, -97.8220),
    ("CN", "China", 35.8617, 104.1954),
    ("BR", "Brazil", -14.2350, -51.9253),
    ("DE", "Germany", 51.1657, 10.4515),
    ("NL", "Netherlands", 52.1326, 5.2913),
    ("FR", "France", 46.2276, 2.2137),
    ("IN", "India", 20.5937, 78.9629),
    ("RU", "Russia", 61.5240, 105.3188),
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def write_json_atomic(path: Path, payload: Any) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(path)


def ip_hash(ip: str) -> str:
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:12]


def fingerprint(*parts: str) -> str:
    raw = "\0".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        ip.version == 4
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_reserved
        and not ip.is_multicast
        and not ip.is_unspecified
    )


def parse_docker_line(line: str) -> tuple[str, str]:
    match = DOCKER_TS_REGEX.match(line)
    if not match:
        return utc_now().isoformat(), line

    raw_ts = match.group("ts")
    message = match.group("message")
    try:
        parsed = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).isoformat(), message
    except ValueError:
        return utc_now().isoformat(), message


def read_logs(container: str) -> str:
    try:
        result = subprocess.run(
            [
                "docker",
                "logs",
                "--timestamps",
                "--since",
                f"{LOG_WINDOW_SECONDS}s",
                container,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return result.stdout + result.stderr
    except Exception:
        return ""


def classify(container: str, line: str) -> tuple[str, str, int, str]:
    text = line.lower()

    if container == "ghostplc-conpot":
        if "modbus" in text or "5020" in text or ":502" in text:
            return "modbus_probe", "modbus", 502, "medium"
        if "s7" in text or "s7comm" in text or "10201" in text or ":102" in text:
            return "s7_probe", "s7", 102, "medium"
        if "snmp" in text or "16100" in text or ":161" in text:
            return "snmp_probe", "snmp", 161, "medium"
        if "http" in text or "8800" in text or ":80" in text:
            return "industrial_http_probe", "http", 80, "low"
        return "ics_probe", "ics", 0, "medium"

    if container == "ghostplc-cowrie":
        if "login attempt" in text or "login" in text:
            return "ssh_login_attempt", "ssh", 2222, "low"
        if "new connection" in text or "connection" in text:
            return "ssh_probe", "ssh", 2222, "low"
        return "ssh_activity", "ssh", 2222, "low"

    return "unknown_probe", "unknown", 0, "low"


def demo_geo(ip: str) -> dict[str, Any]:
    index = int(hashlib.sha256(ip.encode("utf-8")).hexdigest(), 16) % len(DEMO_GEO)
    country_code, country, lat, lon = DEMO_GEO[index]
    return {
        "country_code": country_code,
        "country": country,
        "lat": lat,
        "lon": lon,
        "geo_source": "demo",
    }


def real_geo(ip: str) -> dict[str, Any] | None:
    db_path = os.getenv("GHOSTPLC_GEOIP_DB")
    if not db_path:
        return None

    try:
        import geoip2.database

        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip)
            if not response.location.latitude or not response.location.longitude:
                return None
            return {
                "country_code": response.country.iso_code or "ZZ",
                "country": response.country.name or "Unknown",
                "lat": response.location.latitude,
                "lon": response.location.longitude,
                "geo_source": "maxmind",
            }
    except Exception:
        return None


def locate(ip: str) -> dict[str, Any]:
    return real_geo(ip) or demo_geo(ip)


def collect_events() -> list[dict[str, Any]]:
    cutoff = (utc_now() - timedelta(hours=24)).isoformat()
    recent_keys = {
        fingerprint(
            event["honeypot"],
            event["ts"],
            event["src_ip_hash"],
            event["event_type"],
        )
        for event in read_recent_events(limit=MAX_EVENTS)
        if event.get("ts", "") >= cutoff
    }

    new_events: list[dict[str, Any]] = []

    for container, honeypot_type in CONTAINERS.items():
        for raw_line in read_logs(container).splitlines():
            ts, message = parse_docker_line(raw_line)
            ips = [ip for ip in IP_REGEX.findall(message) if is_public_ipv4(ip)]
            if not ips:
                continue

            src_ip = ips[0]
            event_type, protocol, port, severity = classify(container, message)
            event_fingerprint = fingerprint(container, ts, ip_hash(src_ip), event_type)

            if event_fingerprint in recent_keys:
                continue

            geo = locate(src_ip)
            new_events.append(
                {
                    "event_key": event_fingerprint,
                    "ts": ts,
                    "src_ip_hash": ip_hash(src_ip),
                    "country_code": geo["country_code"],
                    "country": geo["country"],
                    "lat": geo["lat"],
                    "lon": geo["lon"],
                    "geo_source": geo["geo_source"],
                    "protocol": protocol,
                    "port": port,
                    "event_type": event_type,
                    "honeypot": container,
                    "honeypot_type": honeypot_type,
                    "severity": severity,
                }
            )
            recent_keys.add(event_fingerprint)

    insert_events(new_events)

    if EXPORT_EVENTS_JSON:
        write_json_atomic(EVENTS_FILE, read_recent_events(limit=MAX_EVENTS))

    return new_events


if __name__ == "__main__":
    created = collect_events()
    print(f"created={len(created)}")
