import json
from pathlib import Path
import tempfile
import unittest

from as_engine.parser import ParseDiagnostics, iter_eve_alerts, normalize_event


class ParserTests(unittest.TestCase):
    def test_response_alert_is_correlated_to_flow_roles(self) -> None:
        events = [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "event_type": "alert",
                "flow_id": 42,
                "tx_id": 0,
                "src_ip": "10.0.0.20",
                "src_port": 80,
                "dest_ip": "203.0.113.10",
                "dest_port": 41000,
                "proto": "TCP",
                "app_proto": "http",
                "alert": {
                    "signature_id": 2006448,
                    "rev": 4,
                    "signature": "SQLi response",
                    "category": "Web Application Attack",
                    "severity": 2,
                },
                "http": {"status": 200},
            },
            {
                "event_type": "http",
                "flow_id": 42,
                "tx_id": 0,
                "src_ip": "203.0.113.10",
                "src_port": 41000,
                "dest_ip": "10.0.0.20",
                "dest_port": 80,
                "proto": "TCP",
                "app_proto": "http",
                "http": {
                    "hostname": "victim.local",
                    "url": "/search?q=UNIONSELECTpassword",
                    "http_method": "GET",
                    "status": 200,
                    "http_user_agent": "curl/8.0",
                },
            },
            {
                "event_type": "flow",
                "flow_id": 42,
                "src_ip": "203.0.113.10",
                "src_port": 41000,
                "dest_ip": "10.0.0.20",
                "dest_port": 80,
                "proto": "TCP",
                "app_proto": "http",
                "community_id": "1:test",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eve.json"
            with path.open("w", encoding="utf-8") as handle:
                handle.write(json.dumps(events[0]) + "\n")
                handle.write("not-json\n")
                handle.write(json.dumps(events[1]) + "\n")
                handle.write(json.dumps(events[2]) + "\n")
            diagnostics = ParseDiagnostics()
            alerts = list(iter_eve_alerts(str(path), diagnostics))

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.packet_src_ip, "10.0.0.20")
        self.assertEqual(alert.client_ip, "203.0.113.10")
        self.assertEqual(alert.server_ip, "10.0.0.20")
        self.assertEqual(alert.attacker_candidate, "203.0.113.10")
        self.assertEqual(alert.alert_direction, "to_client")
        self.assertEqual(alert.http_url, "/search?q=UNIONSELECTpassword")
        self.assertEqual(alert.community_id, "1:test")
        self.assertEqual(diagnostics.malformed_json, 1)
        self.assertEqual(diagnostics.correlated_alerts, 1)

    def test_port_heuristic_handles_response_without_flow_event(self) -> None:
        event = {
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "alert",
            "flow_id": 7,
            "src_ip": "10.0.0.20",
            "src_port": 80,
            "dest_ip": "203.0.113.10",
            "dest_port": 42000,
            "proto": "TCP",
            "app_proto": "http",
            "alert": {"signature_id": 1, "rev": 1},
        }
        alert = normalize_event(event)
        assert alert is not None
        self.assertEqual(alert.client_ip, "203.0.113.10")
        self.assertEqual(alert.server_ip, "10.0.0.20")
        self.assertEqual(alert.alert_direction, "to_client")
        self.assertEqual(alert.role_confidence, "medium")


if __name__ == "__main__":
    unittest.main()
