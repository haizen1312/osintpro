import unittest


def hex_to_rgb(value):
    value = value.strip().lstrip("#")
    if len(value) == 3:
        value = "".join(ch * 2 for ch in value)
    return tuple(int(value[index:index + 2], 16) / 255 for index in (0, 2, 4))


def srgb_to_linear(channel):
    if channel <= 0.03928:
        return channel / 12.92
    return ((channel + 0.055) / 1.055) ** 2.4


def luminance(rgb):
    red, green, blue = [srgb_to_linear(channel) for channel in rgb]
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast_ratio(foreground, background):
    fg_lum = luminance(hex_to_rgb(foreground))
    bg_lum = luminance(hex_to_rgb(background))
    light = max(fg_lum, bg_lum)
    dark = min(fg_lum, bg_lum)
    return (light + 0.05) / (dark + 0.05)


class ColorContrastTest(unittest.TestCase):
    """Guard core UI tokens against low-contrast rebrand regressions."""

    CASES = {
        "info text on paper": ("#234757", "#f7f5f0", 9.13),
        "info text on panel": ("#234757", "#fffaf2", 9.58),
        "primary ink on paper": ("#0d1117", "#f7f5f0", 17.37),
        "accent link on paper": ("#8f3326", "#f7f5f0", 7.22),
        "low severity on paper": ("#2f6f46", "#f7f5f0", 5.53),
        "code text on dark": ("#d9fff6", "#020807", 18.82),
        "medium severity on paper": ("#6f4c0f", "#f7f5f0", 7.09),
        "pdf muted on white": ("#667069", "#ffffff", 5.14),
    }

    def test_core_text_colors_meet_wcag_aa(self):
        failures = []
        for name, (foreground, background, expected_min) in self.CASES.items():
            ratio = contrast_ratio(foreground, background)
            if ratio < 4.5:
                failures.append(f"{name}: {ratio:.2f}:1")
            self.assertGreaterEqual(
                ratio,
                4.5,
                f"{name} contrast is {ratio:.2f}:1, expected >= 4.5:1",
            )
            self.assertAlmostEqual(
                ratio,
                expected_min,
                delta=0.08,
                msg=f"{name} contrast changed unexpectedly",
            )
        self.assertFalse(failures, ", ".join(failures))


if __name__ == "__main__":
    unittest.main()
