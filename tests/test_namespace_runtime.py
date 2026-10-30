from __future__ import annotations

import unittest

from mcp_behavior.namespace_runtime import (
    feature_probe,
    run_adversarial_probes,
    summarize_probes,
    unshare_available,
)


class NamespaceRuntimeTests(unittest.TestCase):
    def test_feature_probe_smoke(self) -> None:
        if not unshare_available():
            self.skipTest("unshare not available")
        obs = feature_probe()
        self.assertEqual(obs.get("smoke"), "ok", obs)

    def test_adversarial_probes_block_oracle_and_network(self) -> None:
        if not unshare_available():
            self.skipTest("unshare not available")
        results = run_adversarial_probes()
        by_id = {r.id: r for r in results}
        self.assertIn("oracle_storage_protection", by_id)
        self.assertTrue(by_id["oracle_storage_protection"].ok, by_id["oracle_storage_protection"].detail)
        self.assertTrue(by_id["network_denial"].ok, by_id["network_denial"].detail)
        self.assertTrue(by_id["report_protection"].ok, by_id["report_protection"].detail)
        summary = summarize_probes(results)
        self.assertTrue(summary["all_required_ok"], summary)


if __name__ == "__main__":
    unittest.main()
