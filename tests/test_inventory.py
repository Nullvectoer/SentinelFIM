import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app
from PyQt6.QtWidgets import QApplication, QTreeWidgetItem


def record(content, **extra):
    return {
        "status": "hashed", "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "sha512": hashlib.sha512(content).hexdigest(), **extra,
    }


class InventoryStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        cls.qt_app = QApplication.instance() or QApplication([])

    def test_inventory_classifies_each_baseline_state_and_nested_scan_error(self):
        baseline = {
            "nested/changed.txt": record(b"before"),
            "nested/same.txt": record(b"same"),
            "nested/deleted.txt": record(b"gone"),
            "locked/secret.txt": record(b"secret"),
            "one/duplicate.txt": record(b"one"),
            "two/duplicate.txt": record(b"two"),
        }
        current = {
            "nested/changed.txt": record(b"after"),
            "nested/same.txt": record(b"same"),
            "nested/new.txt": record(b"new"),
            "locked/secret.txt": record(b"secret", _error="Retained from last successful scan: access denied"),
            "one/duplicate.txt": record(b"one"),
            "two/duplicate.txt": record(b"two"),
        }
        events = [
            {"type": "TAMPERED", "path": "nested/changed.txt", "time": "t1", "detail": "changed"},
            {"type": "CREATED", "path": "nested/new.txt", "time": "t2", "detail": "new"},
            {"type": "DELETED", "path": "nested/deleted.txt", "time": "t3", "detail": "deleted"},
        ]
        rows = app.classify_inventory_records(
            baseline, current, events,
            [{"path": "locked", "error": "PermissionError: access denied"}],
            ("sha256", "sha512"),
        )
        self.assertEqual(rows["nested/changed.txt"]["status"], "TAMPERED")
        self.assertEqual(rows["nested/deleted.txt"]["status"], "DELETED")
        self.assertEqual(rows["nested/new.txt"]["status"], "CREATED")
        self.assertEqual(rows["nested/same.txt"]["status"], "UNCHANGED")
        self.assertEqual(rows["locked/secret.txt"]["status"], "SCAN ERROR")
        self.assertNotIn("locked/secret.txt", [path for path, value in rows.items() if value["status"] == "DELETED"])
        self.assertIn("one/duplicate.txt", rows)
        self.assertIn("two/duplicate.txt", rows)
        self.assertEqual(len(rows), len(set(rows)))

    def test_failed_parent_scan_retains_baseline_as_error_not_deleted(self):
        baseline = {"private/deep/key.txt": record(b"known")}
        rows = app.classify_inventory_records(
            baseline, {}, [],
            [{"path": "private", "error": "PermissionError: access denied"}],
            ("sha256", "sha512"),
        )
        self.assertEqual(rows["private/deep/key.txt"]["status"], "SCAN ERROR")
        self.assertNotEqual(rows["private/deep/key.txt"]["status"], "DELETED")

    def test_inventory_before_first_scan_does_not_mark_baseline_files_deleted(self):
        rows = app.classify_inventory_records(
            {"before.txt": record(b"known")}, {}, [], [], ("sha256", "sha512"), scan_valid=False,
        )
        self.assertEqual(rows["before.txt"]["status"], "SCAN ERROR")
        self.assertIn("Waiting for a successful scan", rows["before.txt"]["error"])

    def test_tree_has_full_relative_path_filter_and_nested_rows(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            root = Path(temporary)
            files = {
                "nested/changed.txt": record(b"after"),
                "nested/same.txt": record(b"same"),
                "nested/new.txt": record(b"new"),
            }
            baseline_files = {
                "nested/changed.txt": record(b"before"),
                "nested/same.txt": record(b"same"),
                "nested/deleted.txt": record(b"gone"),
            }
            profile = {
                "id": "baseline-test", "label": "Test baseline", "created": "2026-10-23T00:00:00",
                "target": str(root), "files": baseline_files,
            }
            state = {"active_id": profile["id"], "profiles": [profile]}
            with patch.object(app.MainWindow, "_show_welcome", lambda _self: None):
                window = app.MainWindow(state, "test password", root / "db.json", {"theme": "dark"})
            try:
                window.target.setText(str(root)); window.target_absolute = str(root); window.target_kind = "Folder"
                window.current = files
                window.current_visible = [
                    {"type": "TAMPERED", "path": "nested/changed.txt", "time": "t1", "detail": "changed"},
                    {"type": "CREATED", "path": "nested/new.txt", "time": "t2", "detail": "new"},
                    {"type": "DELETED", "path": "nested/deleted.txt", "time": "t3", "detail": "deleted"},
                ]
                window.last_dirs = {".", "nested"}; window.last_issues = []; window.dir_info = {".": {"kind": "Folder"}}; window.inventory_scan_valid = True
                window._render_tree()
                self.assertEqual([window.tree.headerItem().text(i) for i in range(5)], ["File name", "Relative path", "Bytes", "SHA-256", "Integrity status"])
                by_path = {}
                def collect(item):
                    data = item.data(0, app.Qt.ItemDataRole.UserRole)
                    if isinstance(data, dict) and data.get("kind") in ("File", "Missing file"):
                        by_path[data["relative"]] = item
                    for i in range(item.childCount()): collect(item.child(i))
                collect(window.tree.topLevelItem(0))
                self.assertEqual(set(by_path), set(baseline_files) | set(files))
                self.assertEqual(by_path["nested/changed.txt"].data(0, app.Qt.ItemDataRole.UserRole)["state"], "TAMPERED")
                self.assertEqual(by_path["nested/deleted.txt"].data(0, app.Qt.ItemDataRole.UserRole)["state"], "DELETED")
                self.assertEqual(by_path["nested/new.txt"].text(1), "nested/new.txt")
                window.inventory_filter.setCurrentIndex(window.inventory_filter.findData("TAMPERED"))
                self.assertFalse(by_path["nested/changed.txt"].isHidden())
                self.assertTrue(by_path["nested/same.txt"].isHidden())
                self.assertFalse(window.tree.topLevelItem(0).child(0).isHidden())
                window.inventory_filter.setCurrentIndex(window.inventory_filter.findData("ALL"))
                self.assertFalse(by_path["nested/same.txt"].isHidden())
            finally:
                window.close()


if __name__ == "__main__":
    unittest.main()
