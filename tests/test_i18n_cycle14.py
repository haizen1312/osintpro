import json
import unittest
from pathlib import Path

import server


class I18nCycle14Tests(unittest.TestCase):
    def test_locale_files_have_matching_keys(self):
        root = Path(server.ROOT) / "i18n"
        english = json.loads((root / "en.json").read_text(encoding="utf-8"))

        def flatten(payload, prefix=""):
            keys = set()
            for key, value in payload.items():
                name = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    keys.update(flatten(value, name))
                else:
                    keys.add(name)
            return keys

        expected = flatten(english)
        for lang in ("it", "es", "fr", "de", "pt"):
            localized = json.loads((root / f"{lang}.json").read_text(encoding="utf-8"))
            self.assertEqual(expected, flatten(localized), lang)

    def test_finding_template_populates_all_owner_ready_blocks(self):
        finding = server.public_finding(
            "low",
            "CAA missing",
            "The domain does not publicly restrict which CAs can issue certificates.",
            "abuse",
            "impact",
            "action",
            "evidence",
            "caa",
            "caa_missing",
        )
        for lang in ("en", "it", "es", "fr", "de", "pt"):
            translated = server.translate_finding_item(finding, lang)
            for key in ("title", "detail", "abuse_path", "business_impact", "owner_action", "evidence_to_collect"):
                self.assertTrue(translated[key], f"{lang}:{key}")
            if lang != "en":
                self.assertNotEqual("CAA missing", translated["title"])

    def test_translate_report_changes_finding_language_without_mutating_source(self):
        report = {"findings": [server.public_finding("low", "CAA missing", "detail", "abuse", "impact", "action", "evidence", "caa", "caa_missing")]}
        translated = server.translate_report(report, "it")
        self.assertNotEqual(report["findings"][0]["title"], translated["findings"][0]["title"])
        self.assertEqual("CAA missing", report["findings"][0]["title"])


if __name__ == "__main__":
    unittest.main()
