import queue
import tempfile
import time
import unittest
from pathlib import Path

from PyQt6.QtCore import QCoreApplication, Qt

import app


class LongRunMonitorIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt_app = QCoreApplication.instance() or QCoreApplication([])

    def test_monitor_remains_stable_through_repeated_nested_file_changes(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            root = Path(temporary) / "watch-root"
            deep = root / "level-one" / "level-two"
            deep.mkdir(parents=True)
            (deep / "keep.txt").write_text("trusted content\n", encoding="utf-8")
            (deep / "remove.txt").write_text("will be deleted\n", encoding="utf-8")

            initial = app.scan_tree(root, True, 64 * 1024**2, [])
            baseline = {"files": initial["files"]}
            trusted_hashes = {path: (record["sha256"], record["sha512"]) for path, record in baseline["files"].items()}
            results = queue.Queue()
            worker = app.MonitorWorker()
            worker.configure({
                "target": str(root), "recursive": True, "max_bytes": 64 * 1024**2,
                "interval": 0.4, "excludes": [], "methods": ("sha256", "sha512"),
            }, baseline)
            worker.scan_ready.connect(lambda result: results.put(result), Qt.ConnectionType.DirectConnection)
            started = time.monotonic()

            def next_scan(timeout=4.0):
                return results.get(timeout=timeout)

            def scan_until(predicate, timeout=5.0):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    result = next_scan(max(0.1, deadline - time.monotonic()))
                    if predicate(result):
                        return result
                self.fail("Expected filesystem state did not appear in time")

            worker.start()
            try:
                first = next_scan()
                self.assertEqual(first["new_events"], [])
                self.assertIn("level-one/level-two", first["directories"])

                # Hold the watcher in steady state for repeated background scans.
                for _ in range(7):
                    stable = next_scan()
                    self.assertEqual(stable["new_events"], [])
                    self.assertEqual(stable["events"], [])

                created_path = deep / "new.txt"
                created_path.write_text("created during monitoring\n", encoding="utf-8")
                created = scan_until(lambda r: any(e["type"] == "CREATED" and e["path"] == "level-one/level-two/new.txt" for e in r["new_events"]))
                self.assertIn("CREATED", {event["type"] for event in created["events"]})

                # A confirmed incident must remain visible against the original baseline.
                for _ in range(3):
                    persistent = next_scan()
                    self.assertTrue(any(e["type"] == "CREATED" and e["path"].endswith("new.txt") for e in persistent["events"]))
                    self.assertEqual(persistent["new_events"], [])

                (deep / "keep.txt").write_text("tampered content with more bytes\n", encoding="utf-8")
                modified = scan_until(lambda r: any(e["type"] == "TAMPERED" and e["path"].endswith("keep.txt") for e in r["new_events"]))
                self.assertTrue(any(e["type"] == "TAMPERED" for e in modified["events"]))
                for _ in range(3):
                    persistent = next_scan()
                    self.assertTrue(any(e["type"] == "TAMPERED" and e["path"].endswith("keep.txt") for e in persistent["events"]))

                (deep / "remove.txt").unlink()
                deleted = scan_until(lambda r: any(e["type"] == "DELETED" and e["path"].endswith("remove.txt") for e in r["new_events"]))
                self.assertTrue(any(e["type"] == "DELETED" for e in deleted["events"]))

                # Continue running after all event types, and ensure history does not
                # flood with duplicate fresh alerts while current deviations persist.
                for _ in range(40):
                    final_scan = next_scan()
                    self.assertTrue({"CREATED", "TAMPERED", "DELETED"}.issubset({e["type"] for e in final_scan["events"]}))
                    self.assertEqual(final_scan["new_events"], [])
            finally:
                worker.stop()
                worker.wait(5000)

            self.assertFalse(worker.isRunning())
            self.assertEqual(
                {path: (record["sha256"], record["sha512"]) for path, record in baseline["files"].items()},
                trusted_hashes,
                "Monitoring must compare to the original trusted snapshot without rewriting it.",
            )
            self.assertGreaterEqual(time.monotonic() - started, 20.0)


if __name__ == "__main__":
    unittest.main()
