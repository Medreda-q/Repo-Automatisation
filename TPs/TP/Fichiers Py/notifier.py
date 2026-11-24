import requests


def notify_console(summary: list, threshold: int = 5):
    critical = [s for s in summary if s["count"] >= threshold]
    if not critical:
        print("[INFO] Aucune IP au-dessus du seuil.")
        return
    print(f"\n=== {len(critical)} IP(s) suspectes (seuil={threshold}) ===")
    for item in critical:
        print(f" • {item['src_ip']:18} count={item['count']:3} "
              f"sev_max={item['max_severity']} hosts={item['hosts']}")


def notify_webhook(summary: list, webhook_url: str, threshold: int = 5):
    critical = [s for s in summary if s["count"] >= threshold]
    if not critical:
        return
    payload = {
        "source": "tp-wazuh-automatisation",
        "threshold": threshold,
        "count_ips": len(critical),
        "ips": [
            {"ip": i["src_ip"], "count": i["count"],
             "max_severity": i["max_severity"], "hosts": i["hosts"]}
            for i in critical[:20]
        ],
    }
    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        r.raise_for_status()
        print(f"[OK] Webhook envoyé → {webhook_url} (status {r.status_code})")
    except requests.RequestException as e:
        print(f"[ERREUR] Webhook injoignable: {e}")
