from collections import defaultdict
from datetime import datetime, timezone


def parse_ts(value: str) -> datetime:
    """strptime : fromisoformat (Python 3.9) refuse le format +0000."""
    value = value.replace("Z", "+0000")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError(f"timestamp non reconnu: {value}")


def group_by_ip_and_period(events: list, window_minutes: int = 60) -> list:
    groups = defaultdict(list)
    for ev in events:
        if not ev.get("src_ip") or not ev.get("timestamp"):
            continue
        try:
            ts = parse_ts(ev["timestamp"])
        except ValueError:
            continue
        # fenêtre calculée en secondes (epoch) : marche pour toute durée
        window_s = window_minutes * 60
        start = int(ts.timestamp()) // window_s * window_s
        bucket = datetime.fromtimestamp(start, tz=timezone.utc)
        groups[(ev["src_ip"], bucket.isoformat())].append(ev)

    summary = []
    for (ip, period), items in groups.items():
        summary.append({
            "src_ip": ip,
            "period": period,
            "count": len(items),
            "max_severity": max((i.get("severity") or 0) for i in items),
            "hosts": sorted({i["host"] for i in items if i.get("host")}),
            "rules": sorted({str(i["rule_id"]) for i in items if i.get("rule_id")}),
        })
    return sorted(summary, key=lambda x: -x["count"])
