import hashlib
import json
import stat
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import app


class FileIntegrityMonitorTests(unittest.TestCase):
    def test_recursive_scan_hashes_duplicate_names_as_distinct_relative_paths(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            root = Path(temporary)
            (root / "one").mkdir()
            (root / "two" / "nested").mkdir(parents=True)
            (root / "one" / "shared.txt").write_bytes(b"first")
            (root / "two" / "nested" / "shared.txt").write_bytes(b"second")

            result = app.scan_tree(root, True, 1024**2, [])

            self.assertEqual(set(result["files"]), {"one/shared.txt", "two/nested/shared.txt"})
            self.assertIn("two/nested", result["directories"])
            self.assertEqual(result["files"]["one/shared.txt"]["sha256"], hashlib.sha256(b"first").hexdigest())
            self.assertEqual(result["files"]["two/nested/shared.txt"]["sha512"], hashlib.sha512(b"second").hexdigest())

    def test_created_modified_and_deleted_nested_files_are_reported(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            root = Path(temporary)
            (root / "nested").mkdir()
            (root / "nested" / "change.txt").write_text("original", encoding="utf-8")
            (root / "nested" / "remove.txt").write_text("remove me", encoding="utf-8")
            baseline_scan = app.scan_tree(root, True, 1024**2, [])
            baseline = {"files": {key: app.public_record(value) for key, value in baseline_scan["files"].items()}}

            (root / "nested" / "change.txt").write_text("changed content", encoding="utf-8")
            (root / "nested" / "remove.txt").unlink()
            (root / "nested" / "new.txt").write_text("new", encoding="utf-8")
            current = app.scan_tree(root, True, 1024**2, [])
            events = app.detect_events(baseline, current, current["issues"], ("sha256", "sha512"))

            self.assertEqual({(event["type"], event["path"]) for event in events}, {
                ("TAMPERED", "nested/change.txt"),
                ("DELETED", "nested/remove.txt"),
                ("CREATED", "nested/new.txt"),
            })

    def test_scan_errors_retain_prior_files_and_do_not_report_false_deletions(self):
        prior = {"private/secret.txt": {
            "status": "hashed", "size": 7, "mtime_ns": 1, "created_ns": 1,
            "sha256": hashlib.sha256(b"secret").hexdigest(),
            "sha512": hashlib.sha512(b"secret").hexdigest(),
        }}
        issues = [{"path": "private", "error": "PermissionError: access denied"}]
        retained = app.retain_unavailable(prior, {}, issues)
        events = app.detect_events({"files": prior}, {"files": retained}, issues, ("sha256", "sha512"))

        self.assertIn("private/secret.txt", retained)
        self.assertEqual(events, [])

    def test_scan_errors_keep_last_known_nested_folders_in_inventory(self):
        previous = {"private", "private/deep"}
        previous_info = {"private": {"kind": "Folder"}, "private/deep": {"kind": "Folder"}}
        current = {"."}
        current_info = {".": {"kind": "Folder"}}
        issues = [{"path": "private", "error": "PermissionError: access denied"}]

        retained = app.retain_unavailable_directories(previous, current, previous_info, issues, current_info)

        self.assertEqual(retained, {".", "private", "private/deep"})
        self.assertEqual(current_info["private/deep"], {"kind": "Folder"})

    def test_acknowledged_alert_can_recur_after_the_problem_is_resolved(self):
        event = {"signature": ("TAMPERED", "nested/file.txt", "digest", 10)}
        seen, acknowledged = set(), set()
        visible, fresh = app.update_alert_lifecycle([event], seen, acknowledged)
        self.assertEqual((visible, fresh), ([event], [event]))

        acknowledged.add(event["signature"])
        visible, fresh = app.update_alert_lifecycle([event], seen, acknowledged)
        self.assertEqual((visible, fresh), ([], []))

        app.update_alert_lifecycle([], seen, acknowledged)
        visible, fresh = app.update_alert_lifecycle([event], seen, acknowledged)
        self.assertEqual((visible, fresh), ([event], [event]))

    def test_signed_database_round_trip_and_tamper_detection(self):
        state = {"active_id": None, "profiles": []}
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            path = Path(temporary) / "baselines.json"
            app.save_db(path, state, "a sufficiently long test password")
            loaded, error, migrated = app.load_db(path, "a sufficiently long test password")
            self.assertIsNone(error)
            self.assertFalse(migrated)
            self.assertEqual(loaded, state)

            document = json.loads(path.read_text(encoding="utf-8"))
            document["active_id"] = "altered"
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded, error, _ = app.load_db(path, "a sufficiently long test password")
            self.assertIsNone(loaded)
            self.assertIn("INTEGRITY COMPROMISED", error)

    def test_nested_exclusion_matches_folder_names_at_any_depth(self):
        self.assertTrue(app.is_excluded("project/cache/private.bin", {"cache"}))
        self.assertFalse(app.is_excluded("project/cache-file/private.bin", {"cache"}))

    def test_empty_unicode_and_over_limit_files_are_reported_correctly(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            root = Path(temporary)
            (root / "space Δ.txt").write_bytes(b"")
            (root / "large data.bin").write_bytes(b"12345")
            result = app.scan_tree(root, True, 4, [])
            self.assertEqual(result["files"]["space Δ.txt"]["sha256"], hashlib.sha256(b"").hexdigest())
            self.assertEqual(result["files"]["space Δ.txt"]["size"], 0)
            self.assertEqual(result["files"]["large data.bin"]["status"], "excluded")
            self.assertIsNone(result["files"]["large data.bin"]["sha256"])

    def test_rename_event_keeps_both_path_and_hash_fingerprints(self):
        content = b"same content"
        sha256 = hashlib.sha256(content).hexdigest()
        sha512 = hashlib.sha512(content).hexdigest()
        previous = {"files": {"before/readme.txt": {"status": "hashed", "size": len(content), "sha256": sha256, "sha512": sha512}}}
        current = {"files": {"after/readme.txt": {"status": "hashed", "size": len(content), "sha256": sha256, "sha512": sha512}}}
        events = app.detect_events(previous, current, [], ("sha256", "sha512"))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "RENAMED")
        self.assertEqual(events[0]["old_path"], "before/readme.txt")
        self.assertEqual(events[0]["path"], "after/readme.txt")
        self.assertEqual(events[0]["old_hash"], events[0]["new_hash"])
        self.assertEqual(events[0]["old_sha512"], events[0]["new_sha512"])

    def test_symbolic_link_is_rejected_before_file_access(self):
        fake_stat = SimpleNamespace(st_mode=stat.S_IFLNK, st_size=18, st_mtime_ns=123, st_ctime_ns=100)
        path = Path("not-opened-link")
        with patch.object(type(path), "lstat", return_value=fake_stat):
            record = app.scan_file(path, "not-opened-link", 1024)
        self.assertEqual(record["status"], "locked")
        self.assertIsNone(record["sha256"])
        self.assertIn("Symbolic link was not followed", record["_error"])

    def test_scanner_does_not_follow_file_or_root_symlinks(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            outside = Path(temporary) / "outside.txt"
            outside.write_text("outside the monitored scope", encoding="utf-8")
            link = root / "external.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"File symlinks are unavailable: {exc}")

            result = app.scan_tree(root, True, 1024**2, [])
            self.assertIn("external.txt", result["files"])
            self.assertEqual(result["files"]["external.txt"]["status"], "locked")
            self.assertIsNone(result["files"]["external.txt"]["sha256"])
            self.assertTrue(any("Symbolic link was not followed" in issue["error"] for issue in result["issues"]))

            root_link = Path(temporary) / "root-link"
            try:
                root_link.symlink_to(root, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"Directory symlinks are unavailable: {exc}")
            linked_root_scan = app.scan_tree(root_link, True, 1024**2, [])
            self.assertEqual(linked_root_scan["files"], {})
            self.assertTrue(linked_root_scan["issues"])


if __name__ == "__main__":
    unittest.main()
