import unittest
from pathlib import Path

import server


class I18nUiContractTests(unittest.TestCase):
    def test_language_switcher_and_runtime_hooks_are_present(self):
        html = (Path(server.ROOT) / "index.html").read_text(encoding="utf-8")
        app_js = (Path(server.ROOT) / "app.js").read_text(encoding="utf-8")

        self.assertIn('id="languageSelect"', html)
        self.assertIn('value="it"', html)
        self.assertIn('value="pt"', html)
        self.assertIn("function setLanguage", app_js)
        self.assertIn("langParam(download.href)", app_js)
        self.assertIn("lang: state.language", app_js)


if __name__ == "__main__":
    unittest.main()
