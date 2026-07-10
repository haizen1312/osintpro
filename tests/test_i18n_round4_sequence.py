import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class I18nRound4SequenceTests(unittest.TestCase):
    def load_locale(self, lang):
        return json.loads((ROOT / "i18n" / f"{lang}.json").read_text(encoding="utf-8"))

    def test_runtime_translation_switch_starts_from_original_text(self):
        app_js = (ROOT / "app.js").read_text(encoding="utf-8")
        self.assertIn("translationRequestId", app_js)
        self.assertIn("requestId !== state.translationRequestId", app_js)
        self.assertIn('fetch("/api/i18n/en")', app_js)
        self.assertIn("originalTextNodes = new WeakMap()", app_js)
        self.assertIn("originalAttrValues = new WeakMap()", app_js)
        self.assertIn("originalTextNodes.get(node)", app_js)
        self.assertNotIn("translateExactText(node.nodeValue)", app_js)

    def test_positioning_cards_have_badge_title_and_body_i18n(self):
        index_html = (ROOT / "index.html").read_text(encoding="utf-8")
        for card in ("card1", "card2", "card3"):
            for field in ("badge", "title", "body"):
                self.assertIn(f'data-i18n="positioning.{card}.{field}"', index_html)

        for lang in ("en", "it", "es", "fr", "de", "pt"):
            ui = self.load_locale(lang)["ui"]
            for card in ("card1", "card2", "card3"):
                for field in ("badge", "title", "body"):
                    key = f"positioning.{card}.{field}"
                    self.assertTrue(ui.get(key), f"{lang}:{key}")

    def test_workspace_dashboard_reuses_nav_i18n_and_has_metric_i18n(self):
        index_html = (ROOT / "index.html").read_text(encoding="utf-8")
        app_js = (ROOT / "app.js").read_text(encoding="utf-8")
        reused_nav_keys = [
            "nav.domain",
            "nav.social",
            "nav.wallet",
            "nav.web",
            "nav.repo",
            "nav.network",
            "nav.game",
            "nav.history",
            "nav.monitoring",
            "nav.billing",
        ]
        for key in reused_nav_keys:
            self.assertIn(f'data-i18n="{key}"', index_html)

        metric_keys = [
            "dashboard.credits.available_one",
            "dashboard.credits.available_many",
            "dashboard.credits.unlimited",
            "dashboard.graph.count",
            "dashboard.graph.description",
            "dashboard.monitors.description",
        ]
        for key in metric_keys:
            if key.endswith(".description"):
                self.assertIn(f'data-i18n="{key}"', index_html)
            else:
                self.assertIn(key, app_js)
            for lang in ("en", "it", "es", "fr", "de", "pt"):
                self.assertTrue(self.load_locale(lang)["ui"].get(key), f"{lang}:{key}")

        self.assertIn('{count} credit available', self.load_locale("en")["ui"]["dashboard.credits.available_one"])
        self.assertIn('{count} credits available', self.load_locale("en")["ui"]["dashboard.credits.available_many"])
        self.assertNotIn('`${state.user.credits} credits available`', app_js)

    def test_language_sequence_does_not_reuse_previous_language_values(self):
        sequence = ["en", "it", "es", "fr", "de", "pt", "en"]
        locale_ui = {lang: self.load_locale(lang)["ui"] for lang in set(sequence)}
        keys = [
            "positioning.card1.body",
            "positioning.card2.body",
            "positioning.card3.body",
            "nav.domain",
            "nav.social",
            "nav.wallet",
            "nav.web",
            "nav.repo",
            "nav.network",
            "nav.game",
            "nav.history",
            "nav.monitoring",
            "nav.billing",
            "dashboard.credits.available_one",
            "dashboard.graph.count",
            "dashboard.graph.description",
            "dashboard.monitors.description",
        ]

        previous_values = set()
        for lang in sequence:
            rendered = "\n".join(locale_ui[lang][key] for key in keys)
            leaks = [
                value
                for value in previous_values
                if value
                and value not in {"Monitoring", "Billing"}
                and value in rendered
                and value not in set(locale_ui[lang].values())
            ]
            self.assertEqual([], leaks, f"{lang} leaked previous language values")
            previous_values.update(locale_ui[lang][key] for key in keys)


if __name__ == "__main__":
    unittest.main()
