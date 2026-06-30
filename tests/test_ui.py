import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ResponsiveUiTests(unittest.TestCase):
    def test_mobile_navigation_contract_is_present(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        script = (ROOT / "app.js").read_text(encoding="utf-8")
        styles = (ROOT / "styles.css").read_text(encoding="utf-8")

        self.assertIn('name="viewport"', html)
        self.assertIn('id="mobileMenuButton"', html)
        self.assertIn('aria-controls="primaryNavigation"', html)
        self.assertIn("toggleMobileNavigation", script)
        self.assertIn("closeMobileNavigation", script)
        self.assertIn("@media (max-width: 640px)", styles)
        self.assertIn("body.nav-open .nav", styles)
        self.assertIn("min-height: 48px", styles)

    def test_launch_mobile_polish_contract_is_present(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        styles = (ROOT / "styles.css").read_text(encoding="utf-8")

        self.assertIn("Map public evidence. Ship a client-ready dossier.", html)
        self.assertIn("hero-proof", html)
        self.assertIn("Mobile launch polish", styles)
        self.assertIn("@media (max-width: 760px)", styles)
        self.assertIn("overflow-x: hidden", styles)
        self.assertIn("grid-template-columns: minmax(0, 1fr);", styles)
        self.assertIn("#signalCanvas {\n    display: none;", styles)


if __name__ == "__main__":
    unittest.main()
