from __future__ import annotations

import unittest

from mcp_behavior.isolation import (
    ExecutionMode,
    IsolationPolicy,
    NativeBackend,
    NamespaceBackend,
    get_backend,
)


class IsolationTests(unittest.TestCase):
    def test_native_preflight_ok_on_linux(self) -> None:
        backend = NativeBackend()
        result = backend.preflight(IsolationPolicy(mode=ExecutionMode.NATIVE))
        self.assertTrue(result.ok)
        status, reason, evidence = backend.containment_check(result)
        self.assertEqual(status, "UNKNOWN")
        self.assertIn("native", reason.lower())
        self.assertEqual(evidence.get("mode"), "native")

    def test_namespace_preflight_fails_closed_until_implemented(self) -> None:
        backend = NamespaceBackend()
        result = backend.preflight(IsolationPolicy(mode=ExecutionMode.NAMESPACE))
        self.assertFalse(result.ok)
        self.assertTrue(any("launcher_implemented" in r for r in result.reasons()))
        status, reason, evidence = backend.containment_check(result)
        self.assertEqual(status, "UNKNOWN")
        self.assertFalse(evidence.get("preflight_ok", True))

    def test_get_backend(self) -> None:
        self.assertIsInstance(get_backend("native"), NativeBackend)
        self.assertIsInstance(get_backend(ExecutionMode.NAMESPACE), NamespaceBackend)

    def test_no_silent_mode_confusion(self) -> None:
        native = get_backend("native")
        ns = get_backend("namespace")
        self.assertIsNot(type(native), type(ns))
        self.assertEqual(native.mode, ExecutionMode.NATIVE)
        self.assertEqual(ns.mode, ExecutionMode.NAMESPACE)


if __name__ == "__main__":
    unittest.main()
