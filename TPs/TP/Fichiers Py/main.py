#!/usr/bin/env python3
import argparse

from alert_parser import load_alerts, extract_fields
from aggregator import group_by_ip_and_period
from enricher import enrich_mock
from reporter import export_report
from notifier import notify_console, notify_webhook


def main():
    ap = argparse.ArgumentParser(description="TP Wazuh – agrégation alertes")
    ap.add_argument("-i", "--input", required=True, help="Fichier alerts JSON")
    ap.add_argument("-w", "--window", type=int, default=60, help="Fenêtre (min)")
    ap.add_argument("-t", "--threshold", type=int, default=5, help="Seuil notif")
    ap.add_argument("--webhook", default=None, help="URL webhook de test")
    args = ap.parse_args()

    raw = load_alerts(args.input)
    print(f"[+] {len(raw)} alertes chargées")
    parsed = [extract_fields(a) for a in raw]
    parsed = [p for p in parsed if p.get("src_ip")]
    print(f"[+] {len(parsed)} alertes avec src_ip")

    summary = group_by_ip_and_period(parsed, window_minutes=args.window)
    print(f"[+] {len(summary)} groupes IP/période")

    summary = enrich_mock(summary)
    print("[+] Enrichissement (mock) appliqué")

    json_path, csv_path = export_report(summary)
    print(f"[+] Rapport JSON : {json_path}")
    print(f"[+] Rapport CSV : {csv_path}")

    notify_console(summary, threshold=args.threshold)
    if args.webhook:
        notify_webhook(summary, args.webhook, threshold=args.threshold)


if __name__ == "__main__":
    main()
