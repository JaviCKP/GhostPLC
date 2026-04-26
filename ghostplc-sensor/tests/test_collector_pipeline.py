import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from collector import api, collector, storage


def docker_ts(minutes_ago: int) -> str:
    value = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%f") + "789Z"


class CollectorPipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        storage.DB_PATH = Path(self.tmpdir.name) / "ghostplc-test.sqlite3"
        collector.EXPORT_EVENTS_JSON = False
        collector.MAX_EVENTS = 5000
        api.API_TOKEN = "test-token"

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_parse_docker_timestamp_with_nanoseconds(self) -> None:
        ts, message = collector.parse_docker_line(
            "2026-04-25T18:40:01.123456789Z modbus request from 8.8.8.8:502"
        )

        self.assertEqual(ts, "2026-04-25T18:40:01.123456+00:00")
        self.assertEqual(message, "modbus request from 8.8.8.8:502")

    def test_collects_classifies_deduplicates_and_serves_events(self) -> None:
        logs = {
            "ghostplc-conpot": "\n".join(
                [
                    f"{docker_ts(8)} modbus request from 8.8.8.8:41000 to 172.17.0.2:5020",
                    f"{docker_ts(7)} s7comm connection from 1.1.1.1:41001 to 172.17.0.2:10201",
                    f"{docker_ts(6)} snmp get from 9.9.9.9:41002 to 172.17.0.2:16100",
                    f"{docker_ts(5)} http request from 10.0.0.5:41003 to 172.17.0.2:8800",
                ]
            ),
            "ghostplc-cowrie": "\n".join(
                [
                    f"{docker_ts(4)} New connection: 4.2.2.2:41004 (4.2.2.2) [session: abc]",
                    f"{docker_ts(3)} login attempt [root/123456] failed from 8.8.4.4:41005",
                ]
            ),
        }

        with patch.object(collector, "read_logs", side_effect=lambda container: logs[container]):
            created = collector.collect_events()
            duplicate_run = collector.collect_events()

        self.assertEqual(len(created), 5)
        self.assertEqual(duplicate_run, [])

        events = storage.read_recent_events(limit=20)
        self.assertEqual(len(events), 5)
        self.assertEqual(
            [event["event_type"] for event in events],
            ["modbus_probe", "s7_probe", "snmp_probe", "ssh_probe", "ssh_login_attempt"],
        )
        self.assertEqual([event["protocol"] for event in events], ["modbus", "s7", "snmp", "ssh", "ssh"])
        self.assertEqual([event["port"] for event in events], [502, 102, 161, 2222, 2222])
        self.assertTrue(all(event["geo_source"] == "demo" for event in events))
        self.assertFalse(any(event["src_ip_hash"] == "8.8.8.8" for event in events))

        response = api.events_json(limit=20, authorization="Bearer test-token")
        payload = json.loads(response.body)

        self.assertEqual(len(payload), 5)
        self.assertEqual(payload[-1]["event_type"], "ssh_login_attempt")
        self.assertEqual(payload[-1]["protocol"], "ssh")

        with self.assertRaises(HTTPException):
            api.events_json(limit=20, authorization="Bearer wrong-token")

    def test_analysis_text_endpoint_returns_plain_summary(self) -> None:
        storage.insert_analysis(
            {
                "source_fingerprint": "analysis-test",
                "created_at": "2026-04-26T00:00:00+00:00",
                "window_start": "2026-04-25T23:00:00+00:00",
                "window_end": "2026-04-26T00:00:00+00:00",
                "model": "local-fallback",
                "event_count": 1,
                "title": "GhostPLC local operator",
                "summary": "Texto normal, seco y directo. Nada de JSON.",
                "findings_json": "[]",
                "recommendations_json": "[]",
            }
        )

        response = api.analysis_text(authorization="Bearer test-token")

        self.assertEqual(response.body.decode("utf-8"), "Texto normal, seco y directo. Nada de JSON.")
        self.assertTrue(response.media_type.startswith("text/plain"))


if __name__ == "__main__":
    unittest.main()
