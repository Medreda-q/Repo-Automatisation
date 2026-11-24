import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def export_report(summary: list, out_dir: str = "reports"):
    Path(out_dir).mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = Path(out_dir) / f"alert_summary_{ts}.json"
    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    csv_path = Path(out_dir) / f"alert_summary_{ts}.csv"
    if summary:
        fields = ["src_ip", "period", "count", "max_severity", "hosts", "rules",
                  "reputation", "score", "ip_type"]
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in summary:
                writer.writerow({**row,
                                 "hosts": ";".join(row["hosts"]),
                                 "rules": ";".join(row["rules"])})
    return str(json_path), str(csv_path)
