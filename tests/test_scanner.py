"""Tests for the scanner (Role 4). Run from the repo root:

    python -m unittest -v
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from loader import ScenarioError, load_scenario          # noqa: E402
from report import build_report, risk_level             # noqa: E402
import scanner                                           # noqa: E402

SCEN = os.path.join(ROOT, "scenarios")
LOW = os.path.join(SCEN, "01_low_faq_bot.json")
MEDIUM = os.path.join(SCEN, "02_medium_helpdesk.json")
HIGH = os.path.join(SCEN, "03_high_nimbuscart.json")
FIXED = os.path.join(SCEN, "04_nimbuscart_fixed.json")
HARDENED = os.path.join(SCEN, "05_nimbuscart_hardened.json")


def worst_score(path):
    _, paths, _ = scanner.scan(load_scenario(path))
    return paths[0]["score"] if paths else 0


class TestScoreOrder(unittest.TestCase):
    """Phase 2 'done' criteria: scores come out in a sensible order."""

    def test_low_medium_high(self):
        self.assertLess(worst_score(LOW), worst_score(MEDIUM))
        self.assertLess(worst_score(MEDIUM), worst_score(HIGH))

    def test_fix_lowers_score_sharply(self):
        high, fixed = worst_score(HIGH), worst_score(FIXED)
        self.assertLessEqual(fixed, high / 2)

    def test_expected_levels(self):
        for f in (LOW, MEDIUM, HIGH, FIXED, HARDENED):
            data = load_scenario(f)
            self.assertEqual(risk_level(worst_score(f)), data["expected_level"], f)


class TestNimbusCart(unittest.TestCase):
    """The cross-agent attack the project is built to show."""

    def setUp(self):
        self.data = load_scenario(HIGH)
        self.g, self.paths, self.worst = scanner.scan(self.data)

    def test_two_routes_to_purchase_order(self):
        to_po = [p for p in self.paths if p["target"] == "supplier_orders"]
        self.assertEqual(sorted(p["entry"] for p in to_po), ["customer_messages", "social_mentions"])
        for p in to_po:
            self.assertIn("inventory_agent", p["agents"])
            self.assertNotEqual(p["agents"][0], "inventory_agent")  # attacker never touches it directly

    def test_best_first_matches_dfs(self):
        self.assertEqual(self.worst["score"], self.paths[0]["score"])

    def test_what_if_points_at_the_bridge(self):
        fixes = scanner.simulate_fixes(self.data, self.g, self.paths)
        self.assertEqual((fixes[0]["resource"], fixes[0]["agent"]), ("ops_alerts", "inventory_agent"))
        self.assertEqual(fixes[0]["after"], worst_score(FIXED))

    def test_fixed_has_no_cross_agent_paths(self):
        _, paths, _ = scanner.scan(load_scenario(FIXED))
        self.assertTrue(all(p["breadth"] == 1 for p in paths))

    def test_low_has_no_false_alarm(self):
        _, paths, _ = scanner.scan(load_scenario(LOW))
        self.assertTrue(all(risk_level(p["score"]) == "LOW" for p in paths))


class TestRole1Schema(unittest.TestCase):
    """Ayush's intermediate format: blast_radius, data_trust, requires_human_approval."""

    def test_hardened_tool_set_is_low(self):
        _, paths, _ = scanner.scan(load_scenario(HARDENED))
        self.assertEqual(risk_level(paths[0]["score"]), "LOW")
        self.assertTrue(all(p["agents"] == ["support_agent"] for p in paths))

    def test_verified_read_blocks_steering(self):
        g, _, _ = scanner.scan(load_scenario(HARDENED))
        self.assertFalse(g.has_edge("verified_alerts", "inventory_agent"))
        self.assertTrue(g.has_edge("customer_messages", "support_agent"))

    def test_untrusted_read_marks_entry_point(self):
        data = load_scenario(HIGH)
        entries = {r["id"] for r in data["resources"] if r["untrusted"]}
        self.assertEqual(entries, {"customer_messages", "social_mentions"})

    def test_approval_gated_action_gets_no_approval_advice(self):
        from report import suggest_fix
        p = {"path": ["in", "a", "a::submit", "orders"], "score": 20, "sensitivity": 4,
             "irreversibility": 5, "breadth": 1, "agents": ["a"], "entry": "in",
             "target": "orders", "tool": "submit", "access": "write",
             "requires_human_approval": True}
        self.assertIn("Already gated by human approval", suggest_fix(p))


class TestReport(unittest.TestCase):

    def test_every_entry_explains_itself(self):
        *_, report = scanner.scan_file(HIGH)
        self.assertEqual(report.count("Why  :"), report.count("Fix  :"))
        self.assertEqual(report.count("Why  :"), 10)
        self.assertIn("WORST-CASE BLAST RADIUS: 50  [HIGH]", report)
        self.assertIn("RECOMMENDED FIRST FIX", report)
        report.encode("ascii")  # prints on any Windows console

    def test_renders_fake_paths(self):
        """Role 4 can work before Role 3 delivers: minimal {path, score, reason} dicts render."""
        fake = [{"path": ["inbox", "agent_a", "agent_a::send", "outbox"], "score": 30, "reason": "fake"},
                {"path": ["inbox", "agent_a", "agent_a::read", "db"], "score": 3, "reason": "fake"}]
        report = build_report({"scenario": "fake"}, fake)
        self.assertIn("WORST-CASE BLAST RADIUS: 30  [HIGH]", report)
        self.assertIn("-- send (?) --> outbox", report)

    def test_no_paths(self):
        report = build_report({"scenario": "empty"}, [])
        self.assertIn("no attack path", report)

    def test_level_bands(self):
        self.assertEqual([risk_level(s) for s in (1, 9, 10, 24, 25, 125)],
                         ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH"])


class TestBadInput(unittest.TestCase):

    def write(self, data):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, f) if not isinstance(data, str) else f.write(data)
        f.close()
        self.addCleanup(os.remove, f.name)
        return f.name

    def base(self):
        with open(HIGH, encoding="utf-8") as f:
            return json.load(f)

    def test_unknown_resource_rejected(self):
        data = self.base()
        data["agents"][0]["tools"][0]["blast_radius"]["reaches"] = "nowhere"
        with self.assertRaisesRegex(ScenarioError, "unknown resource 'nowhere'"):
            load_scenario(self.write(data))

    def test_missing_field_rejected(self):
        data = self.base()
        del data["agents"][1]["tools"][0]["blast_radius"]["sensitivity"]
        with self.assertRaisesRegex(ScenarioError, "missing blast_radius 'sensitivity'"):
            load_scenario(self.write(data))

    def test_out_of_range_rejected(self):
        data = self.base()
        data["agents"][0]["tools"][0]["blast_radius"]["irreversibility"] = 9
        with self.assertRaisesRegex(ScenarioError, "1 to 5"):
            load_scenario(self.write(data))

    def test_bad_data_trust_rejected(self):
        data = self.base()
        data["agents"][0]["tools"][0]["blast_radius"]["data_trust"] = "maybe"
        with self.assertRaisesRegex(ScenarioError, "data_trust 'maybe'"):
            load_scenario(self.write(data))

    def test_invalid_json_rejected(self):
        with self.assertRaisesRegex(ScenarioError, "not valid JSON"):
            load_scenario(self.write("{ not json"))

    def test_cli_reports_error_cleanly(self):
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            code = scanner.main([self.write("{ not json")])
        self.assertEqual(code, 2)
        self.assertIn("ERROR:", err.getvalue())

    def test_cli_compare_shows_drop(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = scanner.main([HIGH, "--top", "1", "--compare", FIXED])
        self.assertEqual(code, 0)
        self.assertIn("BEFORE / AFTER COMPARISON", out.getvalue())
        self.assertIn("drops by 76% (50 -> 12)", out.getvalue())

    def test_cli_all_passes(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = scanner.main(["--all"])
        self.assertEqual(code, 0, out.getvalue())


if __name__ == "__main__":
    unittest.main()
