import ipaddress


def ip_type(ip: str) -> str:
    try:
        return "private" if ipaddress.ip_address(ip).is_private else "public"
    except ValueError:
        return "invalid"


def enrich_mock(summary: list) -> list:
    """Ajoute reputation, score, enriched et ip_type à chaque groupe."""
    for item in summary:
        if item["count"] >= 20:
            item["reputation"] = "high_risk"
            item["score"] = 90
        elif item["count"] >= 5:
            item["reputation"] = "suspicious"
            item["score"] = 60
        else:
            item["reputation"] = "low"
            item["score"] = 20
        item["ip_type"] = ip_type(item["src_ip"])
        item["enriched"] = True
    return summary
