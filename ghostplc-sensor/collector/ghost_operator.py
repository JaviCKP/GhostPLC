from collections import Counter
from datetime import datetime, timezone
from typing import Any

OT_PROTOCOLS = {"modbus", "s7", "s7comm", "snmp", "ics", "http"}


def parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def percentage(part: int, total: int) -> int:
    if total <= 0:
        return 0
    return round((part / total) * 100)


def count_field(events: list[dict[str, Any]], field: str) -> Counter[str]:
    return Counter(str(event.get(field) or "unknown") for event in events)


def top_items(counter: Counter[str], size: int = 5) -> list[dict[str, Any]]:
    return [{"name": name, "count": count} for name, count in counter.most_common(size)]


def latest_event_ts(events: list[dict[str, Any]]) -> datetime | None:
    timestamps = [parse_ts(event.get("ts")) for event in events]
    parsed = [ts for ts in timestamps if ts is not None]
    return max(parsed) if parsed else None


def age_label(now_dt: datetime, ts_dt: datetime | None) -> str:
    if ts_dt is None:
        return "sin reloj fiable"
    delta = now_dt - ts_dt
    if delta.total_seconds() < 0:
        return "en fecha futura"
    minutes = int(delta.total_seconds() // 60)
    if minutes < 120:
        return f"hace {minutes} min"
    hours = minutes // 60
    if hours < 48:
        return f"hace {hours} h"
    return f"hace {hours // 24} dias"


def compare_windows(events: list[dict[str, Any]], previous_events: list[dict[str, Any]]) -> dict[str, Any]:
    current_count = len(events)
    previous_count = len(previous_events)
    delta = current_count - previous_count
    protocols = count_field(events, "protocol")
    previous_protocols = count_field(previous_events, "protocol")
    countries = count_field(events, "country")
    previous_countries = count_field(previous_events, "country")
    event_types = count_field(events, "event_type")
    severities = count_field(events, "severity")
    ot_count = sum(count for protocol, count in protocols.items() if protocol in OT_PROTOCOLS)

    top_protocol = protocols.most_common(1)[0] if protocols else ("none", 0)
    top_country = countries.most_common(1)[0] if countries else ("none", 0)

    return {
        "event_count": current_count,
        "previous_event_count": previous_count,
        "delta": delta,
        "delta_pct": percentage(delta, previous_count) if previous_count else None,
        "ot_event_count": ot_count,
        "ot_pct": percentage(ot_count, current_count),
        "dominant_protocol": {"name": top_protocol[0], "pct": percentage(top_protocol[1], current_count)},
        "dominant_country": {"name": top_country[0], "pct": percentage(top_country[1], current_count)},
        "top_protocols": top_items(protocols),
        "top_countries": top_items(countries),
        "top_event_types": top_items(event_types),
        "severities": top_items(severities),
        "new_protocols": sorted(set(protocols) - set(previous_protocols)),
        "new_countries": sorted(set(countries) - set(previous_countries))[:5],
    }


def timeline(events: list[dict[str, Any]]) -> dict[str, Any]:
    timestamps = sorted(ts for ts in (parse_ts(event.get("ts")) for event in events) if ts is not None)
    if not timestamps:
        return {"first": None, "last": None, "span_minutes": 0}

    span_seconds = max(0, int((timestamps[-1] - timestamps[0]).total_seconds()))
    return {
        "first": timestamps[0].isoformat(),
        "last": timestamps[-1].isoformat(),
        "span_minutes": max(1, round(span_seconds / 60)) if len(timestamps) > 1 else 0,
    }


def threat_pulse(comparison: dict[str, Any]) -> int:
    count = int(comparison["event_count"])
    previous = int(comparison["previous_event_count"])
    score = min(30, count * 2)
    score += min(25, int(comparison["ot_pct"] * 0.4))
    score += 12 if comparison["new_protocols"] else 0
    score += 8 if comparison["new_countries"] else 0
    score += 15 if previous and count >= max(previous * 2, previous + 10) else 0
    score += 10 if comparison["dominant_protocol"]["pct"] >= 70 and count >= 5 else 0
    return min(99, score)


def confidence(comparison: dict[str, Any], freshness_state: str) -> str:
    count = int(comparison["event_count"])
    if freshness_state in {"stale", "blind"}:
        return "baja"
    if count >= 20:
        return "alta"
    if count >= 5:
        return "media"
    return "baja"


def freshness_state(
    events: list[dict[str, Any]],
    previous_events: list[dict[str, Any]],
    latest_ts: datetime | None,
    now_dt: datetime,
) -> dict[str, Any]:
    if events:
        state = "active"
    elif previous_events:
        state = "quiet"
    elif latest_ts:
        state = "stale"
    else:
        state = "blind"

    return {
        "state": state,
        "latest_event": latest_ts.isoformat() if latest_ts else None,
        "latest_age": age_label(now_dt, latest_ts),
    }


def build_operator_context(
    events: list[dict[str, Any]],
    previous_events: list[dict[str, Any]],
    window_start: str,
    window_end: str,
    now_dt: datetime,
    latest_ts: datetime | None = None,
) -> dict[str, Any]:
    comparison = compare_windows(events, previous_events)
    freshness = freshness_state(events, previous_events, latest_ts or latest_event_ts(events), now_dt)
    pulse = threat_pulse(comparison)

    return {
        "agent": "ghost_operator",
        "tools_used": ["freshness_state", "compare_windows", "timeline", "threat_pulse"],
        "window": {"start": window_start, "end": window_end},
        "freshness": freshness,
        "comparison": comparison,
        "timeline": timeline(events),
        "threat_pulse": pulse,
        "confidence": confidence(comparison, freshness["state"]),
        "style": "voz de terminal industrial, sobria, ironia seca, cero drama",
    }


def operator_findings(context: dict[str, Any], base_findings: list[dict[str, str]]) -> list[dict[str, str]]:
    comparison = context["comparison"]
    freshness = context["freshness"]
    findings = [
        {
            "label": "Estado",
            "detail": f"{freshness['state']} con ultimo evento {freshness['latest_age']}.",
            "severity": "info" if freshness["state"] in {"active", "quiet"} else "medium",
        },
        {
            "label": "Pulso",
            "detail": f"Threat pulse {context['threat_pulse']}/100 con confianza {context['confidence']}.",
            "severity": "high" if context["threat_pulse"] >= 70 else "medium" if context["threat_pulse"] >= 35 else "info",
        },
    ]

    if comparison["dominant_protocol"]["name"] != "none":
        findings.append(
            {
                "label": "Dominante",
                "detail": (
                    f"{comparison['dominant_protocol']['name']} manda en protocolo "
                    f"({comparison['dominant_protocol']['pct']}%)."
                ),
                "severity": "info",
            }
        )

    return (findings + base_findings)[:8]


def compact_operator_context(context: dict[str, Any]) -> dict[str, Any]:
    comparison = context["comparison"]
    return {
        "freshness": context["freshness"],
        "events": comparison["event_count"],
        "previous": comparison["previous_event_count"],
        "delta": comparison["delta"],
        "ot_pct": comparison["ot_pct"],
        "dominant_protocol": comparison["dominant_protocol"],
        "dominant_country": comparison["dominant_country"],
        "new_protocols": comparison["new_protocols"],
        "new_countries": comparison["new_countries"],
        "top_protocols": comparison["top_protocols"][:3],
        "top_countries": comparison["top_countries"][:3],
        "timeline": context["timeline"],
        "threat_pulse": context["threat_pulse"],
        "confidence": context["confidence"],
    }


def fallback_operator_analysis(context: dict[str, Any], findings: list[dict[str, str]]) -> dict[str, Any]:
    comparison = context["comparison"]
    freshness = context["freshness"]
    count = comparison["event_count"]
    previous = comparison["previous_event_count"]
    top_protocols = ", ".join(f"{item['name']}={item['count']}" for item in comparison["top_protocols"][:3]) or "sin datos"
    top_countries = ", ".join(f"{item['name']}={item['count']}" for item in comparison["top_countries"][:3]) or "sin datos"

    if freshness["state"] == "stale":
        summary = (
            "Ghost Operator no ve trafico fresco en la ventana actual. Hay historico en la base, si, muy bonito para "
            f"un museo pequeño; el ultimo evento queda {freshness['latest_age']}.\n\n"
            "Lectura real: silencio reciente, confianza baja y cero permiso para vender actividad vieja como presente. "
            "La consola parpadea, que es su forma barata de parecer ocupada."
        )
    elif count == 0:
        summary = (
            f"Ventana limpia: 0 eventos ahora, {previous} en la anterior. No es gloria defensiva, solo ausencia de ruido "
            "medible en este corte.\n\n"
            f"Estado {freshness['state']}, pulso {context['threat_pulse']}/100 y confianza {context['confidence']}. "
            "El operador archiva el drama en /dev/null, donde suele estar comodo."
        )
    else:
        delta = comparison["delta"]
        sign = "+" if delta >= 0 else ""
        summary = (
            f"Ghost Operator marca {count} eventos en ventana, {sign}{delta} contra la anterior. "
            f"Arriba van {top_protocols}; nada de profecias, solo contadores haciendo su trabajo sucio.\n\n"
            f"Origenes principales: {top_countries}. OT pesa {comparison['ot_pct']}%, pulso {context['threat_pulse']}/100 "
            f"y confianza {context['confidence']}; si esto fuera una alarma vieja, al menos hoy tendria pilas."
        )

    return {
        "title": "Ghost Operator",
        "summary": summary,
        "findings": findings,
        "recommendations": [],
    }
