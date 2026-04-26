import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from .ghost_operator import (
        build_operator_context,
        compact_operator_context,
        fallback_operator_analysis,
        operator_findings,
    )
    from .storage import insert_analysis, read_events_between, read_recent_events
except ImportError:
    from ghost_operator import (
        build_operator_context,
        compact_operator_context,
        fallback_operator_analysis,
        operator_findings,
    )
    from storage import insert_analysis, read_events_between, read_recent_events

MODEL = os.getenv("GHOSTPLC_AI_MODEL", "gpt-5-nano")
ENABLED = os.getenv("GHOSTPLC_AI_ENABLED", "0") == "1"
WINDOW_MINUTES = int(os.getenv("GHOSTPLC_AI_WINDOW_MINUTES", "60"))
STALE_AFTER_MINUTES = int(os.getenv("GHOSTPLC_AI_STALE_AFTER_MINUTES", str(max(WINDOW_MINUTES * 2, 120))))
EVENT_LIMIT = int(os.getenv("GHOSTPLC_AI_EVENT_LIMIT", "1000"))
REASONING_EFFORT = os.getenv("GHOSTPLC_AI_REASONING_EFFORT", "minimal")
OT_PROTOCOLS = {"modbus", "s7", "s7comm", "snmp", "ics", "http"}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_event_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def events_in_window(
    events: list[dict[str, Any]],
    start_dt: datetime,
    end_dt: datetime,
) -> list[dict[str, Any]]:
    fresh_events = []
    for event in events:
        event_ts = parse_event_ts(event.get("ts"))
        if event_ts and start_dt <= event_ts < end_dt:
            fresh_events.append(event)
    return fresh_events


def latest_event_timestamp(events: list[dict[str, Any]]) -> datetime | None:
    timestamps = [parse_event_ts(event.get("ts")) for event in events]
    parsed_timestamps = [ts for ts in timestamps if ts is not None]
    return max(parsed_timestamps) if parsed_timestamps else None


def compact_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "ts": event.get("ts"),
        "country": event.get("country"),
        "geo_source": event.get("geo_source"),
        "protocol": event.get("protocol"),
        "port": event.get("port"),
        "event_type": event.get("event_type"),
        "honeypot_type": event.get("honeypot_type"),
        "severity": event.get("severity"),
    }


def source_fingerprint(events: list[dict[str, Any]], window_start: str, window_end: str) -> str:
    payload = json.dumps(
        {
            "window_start": window_start,
            "window_end": window_end,
            "events": events,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def top_counter(events: list[dict[str, Any]], field: str, size: int = 8) -> list[tuple[str, int]]:
    counter = Counter(str(event.get(field) or "unknown") for event in events)
    return counter.most_common(size)


def count_protocols(events: list[dict[str, Any]]) -> Counter[str]:
    return Counter(str(event.get("protocol") or "unknown") for event in events)


def count_countries(events: list[dict[str, Any]]) -> Counter[str]:
    return Counter(str(event.get("country") or "Unknown") for event in events)


def percentage(part: int, total: int) -> int:
    if total <= 0:
        return 0
    return round((part / total) * 100)


def delta_label(current: int, previous: int) -> str:
    delta = current - previous
    sign = "+" if delta >= 0 else ""
    if previous == 0:
        return f"{sign}{delta} vs ventana previa"
    pct = round((delta / previous) * 100)
    return f"{sign}{delta} ({sign}{pct}%) vs ventana previa"


def detect_findings(events: list[dict[str, Any]], previous_events: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    current_count = len(events)
    previous_count = len(previous_events)
    current_protocols = count_protocols(events)
    previous_protocols = count_protocols(previous_events)
    current_countries = count_countries(events)
    previous_countries = count_countries(previous_events)
    ot_count = sum(count for protocol, count in current_protocols.items() if protocol in OT_PROTOCOLS)

    if current_count == 0:
        findings.append(
            {
                "label": "Silencio",
                "detail": "No hay eventos en la ventana actual. Puede ser normal al arrancar o una exposicion incompleta.",
                "severity": "info",
            }
        )
        return findings

    findings.append(
        {
            "label": "Ritmo",
            "detail": f"{current_count} eventos; {delta_label(current_count, previous_count)}.",
            "severity": "medium" if previous_count and current_count >= previous_count * 2 else "info",
        }
    )

    if previous_count and current_count >= max(previous_count * 2, previous_count + 10):
        findings.append(
            {
                "label": "Pico",
                "detail": "La ventana actual duplica o supera claramente la anterior. Merece mirar protocolo y origen dominante.",
                "severity": "high",
            }
        )

    new_protocols = sorted(set(current_protocols) - set(previous_protocols))
    if new_protocols:
        findings.append(
            {
                "label": "Protocolo nuevo",
                "detail": f"Han aparecido protocolos que no estaban en la ventana previa: {', '.join(new_protocols)}.",
                "severity": "medium",
            }
        )

    new_countries = sorted(set(current_countries) - set(previous_countries))
    if new_countries:
        findings.append(
            {
                "label": "Origen nuevo",
                "detail": f"Nuevos paises en la ventana: {', '.join(new_countries[:5])}.",
                "severity": "info",
            }
        )

    top_protocol, top_protocol_count = current_protocols.most_common(1)[0]
    dominance = percentage(top_protocol_count, current_count)
    if dominance >= 60 and current_count >= 5:
        findings.append(
            {
                "label": "Concentracion",
                "detail": f"{top_protocol} concentra {dominance}% del trafico reciente.",
                "severity": "medium",
            }
        )

    if ot_count:
        findings.append(
            {
                "label": "OT",
                "detail": f"{ot_count} eventos apuntan a superficie industrial ({percentage(ot_count, current_count)}% de la ventana).",
                "severity": "medium",
            }
        )

    return findings[:6]


def event_stats(events: list[dict[str, Any]], previous_events: list[dict[str, Any]]) -> dict[str, Any]:
    current_protocols = count_protocols(events)
    previous_protocols = count_protocols(previous_events)
    current_countries = count_countries(events)
    previous_countries = count_countries(previous_events)
    current_count = len(events)
    previous_count = len(previous_events)
    ot_count = sum(count for protocol, count in current_protocols.items() if protocol in OT_PROTOCOLS)

    return {
        "event_count": current_count,
        "previous_event_count": previous_count,
        "delta": current_count - previous_count,
        "delta_label": delta_label(current_count, previous_count),
        "ot_event_count": ot_count,
        "ot_percentage": percentage(ot_count, current_count),
        "protocols": current_protocols.most_common(8),
        "previous_protocols": previous_protocols.most_common(8),
        "countries": current_countries.most_common(8),
        "previous_countries": previous_countries.most_common(8),
        "event_types": top_counter(events, "event_type", 8),
        "severities": top_counter(events, "severity", 8),
        "new_protocols": sorted(set(current_protocols) - set(previous_protocols)),
        "new_countries": sorted(set(current_countries) - set(previous_countries)),
        "demo_geo": any(event.get("geo_source") == "demo" for event in events),
    }


def fallback_analysis(
    events: list[dict[str, Any]],
    previous_events: list[dict[str, Any]],
    window_start: str,
    window_end: str,
    findings: list[dict[str, str]],
) -> dict[str, Any]:
    now_dt = parse_event_ts(window_end) or utc_now()
    context = build_operator_context(events, previous_events, window_start, window_end, now_dt)
    return fallback_operator_analysis(context, operator_findings(context, findings))


def narrative_is_valid(text: str) -> bool:
    stripped = text.strip()
    lower = stripped.lower()
    paragraphs = [part.strip() for part in stripped.split("\n\n") if part.strip()]
    forbidden_starts = ("{", "[", "```", "-", "*", "1.", "1)", "•", "#")
    forbidden_fragments = ("```", "|---", "<table", "</table>")
    forbidden_recommendations = (
        "recomiendo",
        "recomendaria",
        "conviene",
        "hay que",
        "deberias",
        "deberia",
        "siguiente paso",
        "mitigar",
        "medida",
        "revisar",
        "activar",
        "probar",
        "configurar",
        "cambiar reglas",
    )
    return (
        bool(stripped)
        and len(paragraphs) == 2
        and not stripped.startswith(forbidden_starts)
        and not stripped.startswith("\u2022")
        and not any(fragment in lower for fragment in forbidden_fragments)
        and not any(fragment in lower for fragment in forbidden_recommendations)
        and not lower.lstrip().startswith(("json", "yaml"))
    )


def llm_analysis(
    events: list[dict[str, Any]],
    previous_events: list[dict[str, Any]],
    window_start: str,
    window_end: str,
    findings: list[dict[str, str]],
) -> dict[str, Any]:
    from openai import OpenAI

    now_dt = parse_event_ts(window_end) or utc_now()
    context = build_operator_context(events, previous_events, window_start, window_end, now_dt)
    enriched_findings = operator_findings(context, findings)
    compact_context = compact_operator_context(context)
    client = OpenAI()
    response = client.responses.create(
        model=MODEL,
        reasoning={"effort": REASONING_EFFORT},
        max_output_tokens=320,
        input=[
            {
                "role": "system",
                "content": (
                    "Eres Ghost Operator, agente defensivo de honeypots OT/ICS. "
                    "Escribe en espanol normal: exactamente 2 parrafos cortos. "
                    "Voz de terminal industrial retrofuturista: sobria, seca, con ironia minima y nada cringe. "
                    "Comenta solo evidencias del informe de herramientas: frescura, delta, protocolos, paises, OT, pulso y confianza. "
                    "No devuelvas JSON, YAML, Markdown, tablas, listas, bullets, codigo ni etiquetas. "
                    "No uses muletillas tipo 'observaciones clave', 'en resumen' o 'es importante destacar'. "
                    "No propongas medidas, mitigaciones, recomendaciones, siguientes pasos ni revisiones. "
                    "No inventes malware, actores, CVEs, atribuciones, campanas, intencionalidad ni paises. "
                    "Si hay pocos datos, dilo claro y con poca ceremonia."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Informe compacto de herramientas locales. Responde solo con 2 parrafos de texto, sin recomendaciones.\n"
                    + json.dumps(
                        {
                            "window_start": window_start,
                            "window_end": window_end,
                            "tool_report": compact_context,
                            "local_signals": enriched_findings,
                        },
                        ensure_ascii=True,
                        separators=(",", ":"),
                    )
                ),
            },
        ],
    )

    summary = response.output_text.strip()
    if not narrative_is_valid(summary):
        return fallback_operator_analysis(context, enriched_findings)

    return {
        "title": "Ghost Operator",
        "summary": summary,
        "findings": enriched_findings,
        "recommendations": [],
    }


def run() -> dict[str, Any] | None:
    window_end_dt = utc_now()
    window_start_dt = window_end_dt - timedelta(minutes=WINDOW_MINUTES)
    previous_start_dt = window_start_dt - timedelta(minutes=WINDOW_MINUTES)
    window_start = window_start_dt.isoformat()
    window_end = window_end_dt.isoformat()
    previous_start = previous_start_dt.isoformat()

    raw_events = events_in_window(
        read_events_between(window_start, window_end, limit=EVENT_LIMIT),
        window_start_dt,
        window_end_dt,
    )
    raw_previous_events = events_in_window(
        read_events_between(previous_start, window_start, limit=EVENT_LIMIT),
        previous_start_dt,
        window_start_dt,
    )
    events = [compact_event(event) for event in raw_events]
    previous_events = [compact_event(event) for event in raw_previous_events]
    findings = detect_findings(events, previous_events)

    if not events and not previous_events:
        latest_events = read_recent_events(limit=1)
        if not latest_events:
            return None

        latest_event_dt = latest_event_timestamp(latest_events)
        latest_is_stale = latest_event_dt is None or latest_event_dt < (
            window_end_dt - timedelta(minutes=STALE_AFTER_MINUTES)
        )
        if not latest_is_stale:
            return None

        context = build_operator_context(events, previous_events, window_start, window_end, window_end_dt, latest_event_dt)
        analysis = fallback_operator_analysis(context, operator_findings(context, findings))
        record = {
            "source_fingerprint": source_fingerprint(
                [compact_event(event) for event in latest_events],
                window_start,
                window_end,
            ),
            "created_at": window_end,
            "window_start": window_start,
            "window_end": window_end,
            "model": "local-fallback",
            "event_count": 0,
            "title": analysis["title"][:180],
            "summary": analysis["summary"],
            "findings_json": json.dumps(analysis["findings"], ensure_ascii=True),
            "recommendations_json": json.dumps(analysis["recommendations"], ensure_ascii=True),
        }
        insert_analysis(record)
        return record

    model_name = "local-fallback"
    try:
        analysis = (
            llm_analysis(events, previous_events, window_start, window_end, findings)
            if ENABLED and os.getenv("OPENAI_API_KEY")
            else fallback_analysis(events, previous_events, window_start, window_end, findings)
        )
        if ENABLED and os.getenv("OPENAI_API_KEY") and analysis["title"] == "Ghost Operator":
            model_name = MODEL
    except Exception:
        analysis = fallback_analysis(events, previous_events, window_start, window_end, findings)

    record = {
        "source_fingerprint": source_fingerprint(events + previous_events, window_start, window_end),
        "created_at": window_end,
        "window_start": window_start,
        "window_end": window_end,
        "model": model_name,
        "event_count": len(events),
        "title": analysis["title"][:180],
        "summary": analysis["summary"],
        "findings_json": json.dumps(analysis["findings"], ensure_ascii=True),
        "recommendations_json": json.dumps(analysis["recommendations"], ensure_ascii=True),
    }
    insert_analysis(record)
    return record


if __name__ == "__main__":
    result = run()
    print("analysis=skipped" if result is None else f"analysis=created events={result['event_count']}")
