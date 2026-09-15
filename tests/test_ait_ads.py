import json
from pathlib import Path
import tempfile
import unittest

from as_engine.ait_ads import AitAdsDiagnostics, iter_ait_ads_events


class AitAdsAdapterTests(unittest.TestCase):
    def test_wazuh_embedded_suricata_records_are_converted_without_fabrication(self) -> None:
        records = [
            {
                "rule": {"description": "Suricata: Alert - ET SCAN Test"},
                "data": {
                    "timestamp": "2022-01-21T00:17:54.308261+0000",
                    "proto": "TCP",
                    "src_ip": "10.0.0.1",
                    "src_port": "40000",
                    "dest_ip": "10.0.0.2",
                    "dest_port": "80",
                    "flow_id": "114520921835946.000000",
                    "alert": {
                        "signature_id": "2100001",
                        "rev": "2",
                        "category": "Web Application Attack",
                        "severity": "2",
                    },
                    "http": {"hostname": "example.test", "url": "/scan"},
                },
            },
            {
                "rule": {"description": "Wazuh: Login failed"},
                "data": {"srcip": "10.0.0.3"},
            },
            {
                "rule": {"description": "Suricata: Alert - ET INFO No SID"},
                "data": {"proto": "UDP", "src_ip": "10.0.0.4", "dest_ip": "10.0.0.5"},
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scenario_wazuh.json"
            with path.open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record) + "\n")
                handle.write("not-json\n")
            diagnostics = AitAdsDiagnostics()
            converted = list(iter_ait_ads_events(path, "scenario", diagnostics))

        self.assertEqual(len(converted), 2)
        self.assertEqual(converted[0]["alert"]["signature_id"], 2100001)
        self.assertEqual(converted[0]["alert"]["signature"], "ET SCAN Test")
        self.assertEqual(converted[0]["src_port"], 40000)
        self.assertEqual(converted[0]["flow_id"], 114520921835946)
        self.assertEqual(converted[0]["dataset"]["scenario"], "scenario")
        self.assertNotIn("payload_printable", converted[0])
        self.assertEqual(diagnostics.total_records, 4)
        self.assertEqual(diagnostics.suricata_records, 2)
        self.assertEqual(diagnostics.non_suricata_records, 1)
        self.assertEqual(diagnostics.malformed_json, 1)
        self.assertEqual(diagnostics.missing_sid, 1)


if __name__ == "__main__":
    unittest.main()
