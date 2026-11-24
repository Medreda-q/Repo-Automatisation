import json
from pathlib import Path


def load_alerts(filepath: str) -> list:
    """Lit un fichier JSON (array) ou NDJSON ; ignore les lignes invalides."""
    content = Path(filepath).read_text(encoding="utf-8")
    try:
        data = json.loads(content)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        alerts = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"[WARN] Ligne JSON invalide ignorée : {line[:40]}")
        return alerts


def extract_fields(alert: dict) -> dict:
    """Extrait les champs clés avec .get() (tolère les champs manquants)."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    return {
        "timestamp": alert.get("timestamp"),
        "rule_id": rule.get("id"),
        "severity": rule.get("level"),
        "description": rule.get("description"),
        "host": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "src_ip": data.get("srcip") or data.get("src_ip"),
        "src_user": data.get("srcuser") or data.get("src_user"),
    }
