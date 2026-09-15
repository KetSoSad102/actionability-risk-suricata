from pathlib import Path
import tempfile
import textwrap
import unittest

from as_engine.rule_catalog import RuleCatalog, RuleCatalogError


ROOT = Path(__file__).resolve().parents[1]


class RuleCatalogTests(unittest.TestCase):
    def test_exact_and_revision_fallback_are_explicit(self) -> None:
        catalog = RuleCatalog.from_yaml(str(ROOT / "rules/rule_metadata.yaml"))
        exact = catalog.lookup_with_quality(2016185, 0)
        fallback = catalog.lookup_with_quality(2016185, 99)
        unknown = catalog.lookup_with_quality(9999999, 1)
        self.assertEqual(exact.quality, "exact")
        self.assertEqual(fallback.quality, "sid_fallback")
        self.assertIn("revision mismatch", fallback.warning or "")
        self.assertEqual(unknown.quality, "unknown_sid")

    def test_schema_rejects_invalid_severity(self) -> None:
        content = textwrap.dedent(
            """
            schema_version: 2
            rules:
              - sid: 1
                rev: 1
                severity: 9
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.yaml"
            path.write_text(content, encoding="utf-8")
            with self.assertRaises(RuleCatalogError):
                RuleCatalog.from_yaml(str(path))


if __name__ == "__main__":
    unittest.main()
