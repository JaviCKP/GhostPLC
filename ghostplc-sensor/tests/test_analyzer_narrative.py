import sys
import types
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from collector import analyzer


class FakeResponses:
    last_kwargs = None

    def create(self, **kwargs):
        FakeResponses.last_kwargs = kwargs
        return types.SimpleNamespace(
            output_text=(
                "El radar viene tranquilo, pero no dormido. Hay poco volumen y las senales apuntan "
                "a tanteo automatizado sin base para hablar de campanas.\n\n"
                "Lo interesante esta en el cambio de ritmo: aparece Modbus junto a SSH, asi que el "
                "sensor ya esta oliendo superficie OT y ruido clasico de internet."
            )
        )


class FakeOpenAI:
    def __init__(self):
        self.responses = FakeResponses()


class AnalyzerNarrativeTest(unittest.TestCase):
    def test_fallback_summary_is_plain_text_not_json(self) -> None:
        events = [
            {
                "ts": "2026-04-26T00:00:00+00:00",
                "country": "Germany",
                "geo_source": "demo",
                "protocol": "modbus",
                "port": 502,
                "event_type": "modbus_probe",
                "honeypot_type": "ics",
                "severity": "medium",
            }
        ]
        findings = analyzer.detect_findings(events, [])
        result = analyzer.fallback_analysis(
            events,
            [],
            "2026-04-26T00:00:00+00:00",
            "2026-04-26T01:00:00+00:00",
            findings,
        )
        summary = result["summary"]
        paragraphs = [part for part in summary.split("\n\n") if part.strip()]

        self.assertEqual(len(paragraphs), 2)
        self.assertFalse(summary.lstrip().startswith(("{", "[")))
        self.assertNotIn("```", summary)
        self.assertEqual(result["recommendations"], [])

    def test_narrative_validator_rejects_json_and_long_output(self) -> None:
        self.assertFalse(analyzer.narrative_is_valid('{"summary":"no"}'))
        self.assertFalse(analyzer.narrative_is_valid("[radar] no es texto normal"))
        self.assertFalse(analyzer.narrative_is_valid("1. Hay poco ruido.\n2. Todo viene de India."))
        self.assertFalse(analyzer.narrative_is_valid("1) Hay poco ruido."))
        self.assertFalse(analyzer.narrative_is_valid("• Hay poco ruido."))
        self.assertFalse(analyzer.narrative_is_valid("# Observaciones clave"))
        self.assertFalse(analyzer.narrative_is_valid("Pais | Eventos\n|---|---\nIndia | 2"))
        self.assertFalse(analyzer.narrative_is_valid("<table><tr><td>no</td></tr></table>"))
        self.assertFalse(analyzer.narrative_is_valid("uno\n\ndos\n\ntres\n\ncuatro"))
        self.assertFalse(analyzer.narrative_is_valid("uno"))
        self.assertFalse(analyzer.narrative_is_valid("uno\n\ndos\n\ntres"))
        self.assertFalse(analyzer.narrative_is_valid("uno\n\nConviene revisar el firewall."))
        self.assertFalse(analyzer.narrative_is_valid("uno\n\nSiguiente paso: activar GeoIP."))
        self.assertTrue(analyzer.narrative_is_valid("uno\n\ndos"))

    def test_s7comm_counts_as_ot_surface(self) -> None:
        events = [
            {
                "protocol": "s7comm",
                "country": "Germany",
                "event_type": "s7_probe",
                "severity": "medium",
            }
        ]

        stats = analyzer.event_stats(events, [])
        findings = analyzer.detect_findings(events, [])

        self.assertEqual(stats["ot_event_count"], 1)
        self.assertEqual(stats["ot_percentage"], 100)
        self.assertTrue(any(finding["label"] == "OT" for finding in findings))

    def test_run_does_not_treat_stale_events_as_current_activity(self) -> None:
        stale_event = {
            "ts": "2026-04-20T00:00:00+00:00",
            "country": "Germany",
            "geo_source": "demo",
            "protocol": "modbus",
            "port": 502,
            "event_type": "modbus_probe",
            "honeypot_type": "ics",
            "severity": "medium",
        }
        inserted_records = []

        with (
            patch.object(analyzer, "utc_now", return_value=datetime(2026, 4, 26, 12, 0, tzinfo=timezone.utc)),
            patch.object(analyzer, "read_events_between", return_value=[stale_event]),
            patch.object(analyzer, "read_recent_events", return_value=[stale_event]),
            patch.object(analyzer, "insert_analysis", side_effect=inserted_records.append),
        ):
            result = analyzer.run()

        self.assertIsNotNone(result)
        self.assertEqual(result["event_count"], 0)
        self.assertEqual(result["title"], "Ghost Operator")
        self.assertIn("no ve trafico fresco", result["summary"])
        self.assertIn("historico en la base", result["summary"])
        self.assertEqual(inserted_records, [result])

    def test_llm_call_uses_minimal_reasoning_and_plain_text_prompt(self) -> None:
        fake_openai_module = types.ModuleType("openai")
        fake_openai_module.OpenAI = FakeOpenAI
        events = [
            {
                "ts": "2026-04-26T00:00:00+00:00",
                "country": "Germany",
                "geo_source": "demo",
                "protocol": "modbus",
                "port": 502,
                "event_type": "modbus_probe",
                "honeypot_type": "ics",
                "severity": "medium",
            }
        ]

        with unittest.mock.patch.dict(sys.modules, {"openai": fake_openai_module}):
            result = analyzer.llm_analysis(
                events,
                [],
                "2026-04-26T00:00:00+00:00",
                "2026-04-26T01:00:00+00:00",
                analyzer.detect_findings(events, []),
            )

        kwargs = FakeResponses.last_kwargs
        self.assertIsNotNone(kwargs)
        self.assertEqual(kwargs["reasoning"], {"effort": "minimal"})
        self.assertLessEqual(kwargs["max_output_tokens"], 320)

        prompt_text = " ".join(item["content"] for item in kwargs["input"])
        self.assertIn("Ghost Operator", prompt_text)
        self.assertIn("exactamente 2 parrafos", prompt_text)
        self.assertIn("ironia minima", prompt_text)
        self.assertIn("nada cringe", prompt_text)
        self.assertIn("tool_report", prompt_text)
        self.assertIn("threat_pulse", prompt_text)
        self.assertNotIn("sample_events", prompt_text)
        self.assertIn("No uses muletillas", prompt_text)
        self.assertIn("No propongas medidas", prompt_text)
        self.assertIn("No inventes malware", prompt_text)
        self.assertFalse(result["summary"].lstrip().startswith(("{", "[")))
        self.assertEqual(len([part for part in result["summary"].split("\n\n") if part.strip()]), 2)
        self.assertEqual(result["recommendations"], [])
        self.assertEqual(result["title"], "Ghost Operator")


if __name__ == "__main__":
    unittest.main()
