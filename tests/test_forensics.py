import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app
from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication, QDialog, QPlainTextEdit, QPushButton


def valid_report():
    return {
        "technical_interpretation": "The selected digest differs from the baseline.",
        "potential_impact": "Impact depends on the file's role.",
        "priority_advisory": "HIGH",
        "hypotheses": ["The change may be authorized; the evidence does not establish why."],
        "investigation_steps": ["Check the approved change record."],
        "missing_evidence": ["The responsible process is not recorded."],
    }


class FakeGeminiClient:
    def __init__(self, response=None, error=None, side_effect=None, **kwargs):
        self.kwargs = kwargs
        self.close = Mock()
        self.models = SimpleNamespace(generate_content=Mock(return_value=response, side_effect=side_effect or error))


class ForensicAnalysisTests(unittest.TestCase):
    EVENT = {
        "id": "evt-1", "type": "DELETED", "path": "nested/secret.txt",
        "time": "2026-10-23T12:00:00+05:30", "detail": "File is missing from the monitored folder.",
        "old_size": 19, "new_size": None, "old_hash": "a" * 64,
        "old_sha512": "b" * 128,
    }

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
        cls.qt_app = QApplication.instance() or QApplication([])

    def test_incident_payload_contains_only_selected_incident_evidence(self):
        related = [
            {"id": "evt-2", "type": "TAMPERED", "path": "nested/secret.txt", "time": "12:01"},
            {"id": "evt-3", "type": "CREATED", "path": "other/file.txt", "time": "12:02"},
        ]
        context = app.build_incident_context(self.EVENT, related)
        self.assertEqual(context["baseline_status"], "Present and hashed in selected baseline")
        self.assertEqual(context["current_status"], "Absent from latest successful scan")
        self.assertEqual(context["baseline_sha256"], "a" * 64)
        self.assertNotIn("related_alerts", context)
        self.assertNotIn("file_contents", context)

    def test_settings_expose_configurable_timeout_and_fast_model_default(self):
        settings = app.SettingsDialog({
            "methods": ("sha256", "sha512"), "recursive": True, "max_bytes": 1024**3,
            "interval": 1.0, "excludes": [], "llm_enabled": True,
            "llm_provider": "gemini", "llm_model": app.DEFAULT_GEMINI_MODEL,
            "analysis_timeout_seconds": app.DEFAULT_ANALYSIS_TIMEOUT_SECONDS,
            "llm_api_key": "test-key", "storage_dir": str(Path.cwd()),
        })
        self.assertEqual(settings.model.currentText(), "gemini-3.5-flash-lite")
        self.assertEqual(settings.analysis_timeout.value(), 90)
        self.assertEqual(settings.theme.currentData(), "dark")
        settings.analysis_timeout.setValue(45)
        self.assertEqual(settings.value()["analysis_timeout_seconds"], 45)
        settings.theme.setCurrentIndex(settings.theme.findData("cobalt"))
        self.assertEqual(settings.value()["theme"], "cobalt")
        settings.close()

    def test_all_five_themes_have_distinct_palettes_and_settings_choices(self):
        expected = {
            "dark": "Deep Cyber Dark", "cobalt": "Corporate Cobalt", "midnight": "Midnight Blue",
            "graphite": "Graphite Amber", "arctic": "Arctic Light",
        }
        settings = app.SettingsDialog({
            "methods": ("sha256", "sha512"), "recursive": True, "max_bytes": 1024**3,
            "interval": 1.0, "excludes": [], "llm_enabled": False,
            "storage_dir": str(Path.cwd()),
        })
        try:
            choices = {settings.theme.itemData(index): settings.theme.itemText(index) for index in range(settings.theme.count())}
            self.assertEqual(choices, expected)
            for key in expected:
                stylesheet = app.set_theme(key)
                self.assertEqual(app.ACTIVE_THEME, key)
                self.assertEqual(app.C, app.THEMES[key])
                self.assertIn(app.C["void"], stylesheet)
                self.assertIn(app.C["accent"], stylesheet)
                self.assertIn(f'QLabel#title{{color:{app.C["text"]};', stylesheet)
            def luminance(hex_color):
                channels = [getattr(QColor(hex_color), channel)() / 255 for channel in ("red", "green", "blue")]
                linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
                return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
            panel_luma = luminance(app.THEMES["arctic"]["panel"])
            self.assertGreater((panel_luma + 0.05) / (luminance(app.THEMES["arctic"]["text"]) + 0.05), 12)
            self.assertGreater((panel_luma + 0.05) / (luminance(app.THEMES["arctic"]["muted"]) + 0.05), 7)
        finally:
            app.set_theme("dark")
            settings.close()

    def test_alert_card_details_and_investigate_actions(self):
        event = {
            "id": "evt-ui", "type": "TAMPERED", "path": "tasks/README.md",
            "time": "2026-10-24T10:15:00+05:30", "detail": "SHA-256 changed",
            "old_size": 12, "new_size": 29, "old_hash": "a" * 64,
            "new_hash": "b" * 64, "old_sha512": "c" * 128,
            "new_sha512": "d" * 128,
            "diff": {"removed_lines": ["old task"], "added_lines": ["new task"]},
        }
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(app.MainWindow, "_show_welcome", lambda _self: None):
                window = app.MainWindow({"active_id": None, "profiles": []}, "test database password", Path(folder) / "baselines.json", {"theme": "dark"})
            try:
                destinations = ["Dashboard", "Baseline Manager", "Alerts", "System Inventory", "AI Assistant", "Forensic Analysis"]
                self.assertEqual(list(window.nav_buttons), destinations)
                self.assertFalse(hasattr(window, "theme_select"))
                for destination in destinations:
                    window.nav_buttons[destination].click()
                    self.assertIs(window.page_stack.currentWidget(), window.pages[destination])
                    if destination != "Dashboard":
                        self.assertIsNotNone(window.pages[destination].graphicsEffect())
                window.navigate("Alerts")
                self.assertEqual(window.dashboard_start_btn.text(), "▶  Start monitoring")
                window.events = [event]
                window._new_alert_animation_ids = {event["id"]}
                window._render_ledger()
                card = window.alert_list.itemWidget(window.alert_list.item(0))
                self.assertIsNotNone(card.graphicsEffect())
                actions = {button.text(): button for button in card.findChildren(QPushButton)}
                self.assertIn("Details", actions)
                self.assertIn("Investigate", actions)

                dialog_text = []
                def capture_dialog(dialog):
                    body = dialog.findChild(QPlainTextEdit)
                    dialog_text.append(body.toPlainText() if body else "")
                    return QDialog.DialogCode.Accepted
                with patch.object(QDialog, "exec", capture_dialog):
                    actions["Details"].click()
                self.assertIn("12 → 29 bytes (+17 bytes)", dialog_text[0])
                self.assertIn("README.md", dialog_text[0])
                self.assertIn("Text diff: 1 removed line(s), 1 added line(s)", dialog_text[0])
                self.assertIn("old task", dialog_text[0])

                actions["Investigate"].click()
                self.assertEqual(window.selected_event["id"], "evt-ui")
                self.assertIs(window.page_stack.currentWidget(), window.pages["Forensic Analysis"])
            finally:
                window.close()

    def test_queued_first_scans_reuse_initial_baseline_instead_of_duplicating_it(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "watch_folder"
            target.mkdir()
            with patch.object(app.MainWindow, "_show_welcome", lambda _self: None):
                window = app.MainWindow({"active_id": None, "profiles": []}, "test database password", Path(folder) / "baselines.json", {"theme": "dark"})
            try:
                window.target.setText(str(target))
                record = {"status": "hashed", "size": 4, "sha256": "a" * 64, "sha512": "b" * 128, "mtime_ns": 1}
                result = {
                    "files": {"nested/file.txt": record}, "issues": [], "directories": {".", "nested"},
                    "directory_info": {".": {"kind": "Folder"}}, "absolute_target": str(target),
                    "hash_stats": {"bytes": 4, "sha256_seconds": 0.01, "sha512_seconds": 0.01},
                    "events": [], "new_events": [], "elapsed": 0.01, "baseline_missing": True,
                }
                window.on_scan(dict(result))
                first_id = window.active_profile
                window.on_scan(dict(result))
                self.assertTrue(first_id)
                self.assertEqual(len(window.state["profiles"]), 1)
                self.assertEqual(window.active_profile, first_id)
                self.assertEqual(window.state["profiles"][0]["files"].keys(), {"nested/file.txt"})
            finally:
                window.close()

    def test_missing_file_report_distinguishes_evidence_from_cause(self):
        html = app.forensic_report_html(app.local_incident_report(self.EVENT), self.EVENT)
        self.assertIn("present in the selected baseline", html)
        self.assertIn("latest successful scan", html)
        self.assertIn("does not establish why", html)
        self.assertIn("HYPOTHESES", html)
        self.assertIn("EVIDENCE STILL MISSING", html)
        self.assertNotIn("attacker deleted", html.lower())

    def test_valid_json_response_is_validated_and_single_request_succeeds(self):
        response = SimpleNamespace(text=json.dumps(valid_report()))
        fake = FakeGeminiClient(response=response)
        worker = app.AnalysisWorker({"llm_api_key": "test-key", "llm_model": "gemini-3.5-flash-lite", "analysis_timeout_seconds": 60}, self.EVENT)
        worker.started_at = time.perf_counter()
        results = []
        worker.completed.connect(results.append)
        with patch("google.genai.Client", return_value=fake) as client_factory:
            worker._gemini(worker.settings, "evidence-only prompt", app.build_incident_context(self.EVENT))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["technical_interpretation"], valid_report()["technical_interpretation"])
        self.assertEqual(fake.models.generate_content.call_count, 1)
        config = fake.models.generate_content.call_args.kwargs["config"]
        self.assertEqual(config.response_mime_type, "application/json")
        self.assertEqual(config.thinking_config.thinking_level.value, "LOW")
        http_options = client_factory.call_args.kwargs["http_options"]
        self.assertEqual(http_options.timeout, 60_000)
        self.assertEqual(http_options.retry_options.attempts, 1)

    def test_invalid_json_fails_validation_before_display(self):
        fake = FakeGeminiClient(response=SimpleNamespace(text="not-json"))
        worker = app.AnalysisWorker({"llm_api_key": "test-key"}, self.EVENT)
        worker.started_at = time.perf_counter()
        with patch("google.genai.Client", return_value=fake):
            with self.assertRaisesRegex(ValueError, "invalid JSON"):
                worker._gemini(worker.settings, "prompt", app.build_incident_context(self.EVENT))
        self.assertEqual(fake.models.generate_content.call_count, 1)

    def test_one_503_retry_then_success_is_measured(self):
        response = SimpleNamespace(text=json.dumps(valid_report()))
        transient = RuntimeError("503 UNAVAILABLE")
        transient.code = 503
        fake = FakeGeminiClient(side_effect=[transient, response])
        worker = app.AnalysisWorker({"llm_api_key": "test-key"}, self.EVENT)
        worker.started_at = time.perf_counter()
        results = []
        worker.completed.connect(results.append)
        with patch("google.genai.Client", return_value=fake), patch.object(app.time, "sleep") as sleep:
            worker._gemini(worker.settings, "prompt", app.build_incident_context(self.EVENT))
        self.assertEqual(len(results), 1)
        self.assertEqual(fake.models.generate_content.call_count, 2)
        self.assertEqual(worker.metrics["retry_count"], 1)
        sleep.assert_called_once_with(0.5)

    def test_diagnostic_log_records_model_timeout_retry_and_no_api_key(self):
        secret = "diagnostic-secret-must-not-be-written"
        fake = FakeGeminiClient(response=SimpleNamespace(text=json.dumps(valid_report())))
        worker = app.AnalysisWorker({"llm_api_key": secret, "llm_model": "gemini-3.5-flash-lite", "analysis_timeout_seconds": 30}, self.EVENT)
        worker.started_at = time.perf_counter()
        logger = app.logging.getLogger('fim.analysis'); previous_handlers = list(logger.handlers); logger.handlers.clear()
        try:
            with tempfile.TemporaryDirectory() as folder:
                with patch.object(app, "default_data_dir", return_value=Path(folder)), patch("google.genai.Client", return_value=fake):
                    worker._gemini(worker.settings, "evidence-only prompt", app.build_incident_context(self.EVENT))
                    for handler in app.analysis_logger().handlers: handler.flush()
                    log_text = (Path(folder) / "logs" / "analysis.log").read_text(encoding="utf-8")
                    for handler in logger.handlers: handler.close()
                    logger.handlers.clear()
        finally:
            for handler in logger.handlers: handler.close()
            logger.handlers.clear(); logger.handlers.extend(previous_handlers)
        self.assertIn("model=gemini-3.5-flash-lite", log_text)
        self.assertIn("timeout_ms=30000", log_text)
        self.assertIn("attempt=1", log_text)
        self.assertNotIn(secret, log_text)

    def test_timeout_error_is_useful_and_does_not_leak_key(self):
        secret = "test-secret-that-must-not-be-shown"
        fake = FakeGeminiClient(error=TimeoutError(secret))
        worker = app.AnalysisWorker({"llm_enabled": True, "llm_provider": "gemini", "llm_model": "gemini-3.8-flash", "llm_api_key": secret}, self.EVENT)
        errors = []
        worker.failed.connect(errors.append)
        with patch("google.genai.Client", return_value=fake):
            worker.run()
        self.assertEqual(len(errors), 1)
        self.assertIn("timed out", errors[0])
        self.assertNotIn(secret, errors[0])
        self.assertNotIn(secret, str(worker.metrics))
        self.assertIsNotNone(worker.metrics["total_ms"])

    def test_retryable_503_falls_back_to_local_evidence_report(self):
        transient = RuntimeError("503 UNAVAILABLE")
        transient.code = 503
        fake = FakeGeminiClient(side_effect=[transient, transient])
        worker = app.AnalysisWorker({"llm_enabled": True, "llm_provider": "gemini", "llm_model": "gemini-3.8-flash", "llm_api_key": "test-key"}, self.EVENT)
        results = []
        worker.completed.connect(results.append)
        with patch("google.genai.Client", return_value=fake), patch.object(app.time, "sleep"):
            worker.run()
        self.assertEqual(fake.models.generate_content.call_count, 2)
        self.assertEqual(results[0]["_analysis_source"], "Local rule engine")
        self.assertIn("does not establish why", results[0]["technical_interpretation"])

    def test_cancelled_before_request_emits_cancelled_without_calling_api(self):
        class PreCancelledWorker(app.AnalysisWorker):
            def isInterruptionRequested(self): return True
        fake = FakeGeminiClient(response=SimpleNamespace(text=json.dumps(valid_report())))
        worker = PreCancelledWorker({"llm_enabled": True, "llm_provider": "gemini", "llm_model": "gemini-3.5-flash-lite", "llm_api_key": "test-key"}, self.EVENT)
        cancelled = []
        worker.cancelled.connect(lambda: cancelled.append(True))
        with patch("google.genai.Client", return_value=fake): worker.run()
        self.assertEqual(cancelled, [True])
        self.assertEqual(fake.models.generate_content.call_count, 0)

    def test_theme_preference_round_trip_uses_existing_persistence(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            prefs = root / "preferences.json"
            pointer = root / "storage-location.json"
            with patch.object(app, "preferences_path", return_value=prefs), patch.object(app, "location_pointer_path", return_value=pointer):
                app.save_preferences({"theme": "cobalt", "monitoring": {}}, root)
                self.assertEqual(app.load_preferences()["theme"], "cobalt")

    def test_analysis_finish_handler_always_clears_busy_state(self):
        class Widget:
            def __init__(self): self.calls = []
            def setRange(self, *args): self.calls.append(("range", *args))
            def setValue(self, *args): self.calls.append(("value", *args))
            def hide(self): self.calls.append(("hide",))
            def setEnabled(self, *args): self.calls.append(("enabled", *args))
        progress, status, button = Widget(), Widget(), Widget()
        cancel_button = Widget()
        target = SimpleNamespace(analysis_progress=progress, analysis_status=status, analyze_btn=button, cancel_analysis_btn=cancel_button)
        app.MainWindow._analysis_finished(target)
        self.assertIn(("range", 0, 100), progress.calls)
        self.assertIn(("hide",), progress.calls)
        self.assertIn(("hide",), status.calls)
        self.assertIn(("enabled", True), button.calls)
        self.assertIn(("enabled", False), cancel_button.calls)

    def test_qthread_success_emits_validated_result_and_finishes(self):
        fake = FakeGeminiClient(response=SimpleNamespace(text=json.dumps(valid_report())))
        worker = app.AnalysisWorker({"llm_enabled": True, "llm_provider": "gemini", "llm_model": "gemini-3.8-flash", "llm_api_key": "test-key"}, self.EVENT)
        results, errors, metrics = [], [], []
        loop = QEventLoop()
        worker.completed.connect(results.append)
        worker.failed.connect(errors.append)
        worker.metrics_ready.connect(metrics.append)
        worker.finished.connect(loop.quit)
        with patch("google.genai.Client", return_value=fake):
            worker.start()
            QTimer.singleShot(5000, loop.quit)
            loop.exec()
        self.assertTrue(worker.wait(1000))
        self.assertEqual(len(results), 1)
        self.assertEqual(errors, [])
        self.assertEqual(len(metrics), 1)
        self.assertGreaterEqual(metrics[0]["total_ms"], metrics[0]["request_ms"])

    def test_main_window_restores_controls_after_mocked_analysis_success(self):
        fake = FakeGeminiClient(response=SimpleNamespace(text=json.dumps(valid_report())))
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            with patch.object(app.MainWindow, "_show_welcome", lambda _self: None), patch("google.genai.Client", return_value=fake):
                window = app.MainWindow({"active_id": None, "profiles": []}, "test database password", Path(folder) / "baselines.json", {})
                window.settings.update({"llm_enabled": True, "llm_provider": "gemini", "llm_model": "gemini-3.8-flash", "llm_api_key": "test-key"})
                window.selected_event = dict(self.EVENT)
                window.analyze_selected()
                worker = window.analysis_worker
                loop = QEventLoop()
                worker.finished.connect(loop.quit)
                QTimer.singleShot(5000, loop.quit)
                loop.exec()
                self.qt_app.processEvents()
                self.assertTrue(worker.wait(1000))
                self.assertTrue(window.analyze_btn.isEnabled())
                self.assertTrue(window.analysis_progress.isHidden())
                self.assertTrue(window.analysis_status.isHidden())
                self.assertIn("GEMINI INTERPRETATION", window.report.toHtml())
                self.assertEqual(fake.models.generate_content.call_count, 1)
                window.close()

    def test_main_window_restores_controls_and_shows_sanitized_timeout(self):
        secret = "test-secret-must-not-appear"
        fake = FakeGeminiClient(error=TimeoutError(secret))
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            with patch.object(app.MainWindow, "_show_welcome", lambda _self: None), patch("google.genai.Client", return_value=fake):
                window = app.MainWindow({"active_id": None, "profiles": []}, "test database password", Path(folder) / "baselines.json", {})
                window.settings.update({"llm_enabled": True, "llm_provider": "gemini", "llm_model": "gemini-3.8-flash", "llm_api_key": secret})
                window.selected_event = dict(self.EVENT)
                window.analyze_selected()
                worker = window.analysis_worker
                loop = QEventLoop()
                worker.finished.connect(loop.quit)
                QTimer.singleShot(5000, loop.quit)
                loop.exec()
                self.qt_app.processEvents()
                self.assertTrue(worker.wait(1000))
                self.assertTrue(window.analyze_btn.isEnabled())
                self.assertTrue(window.analysis_progress.isHidden())
                report = window.report.toHtml()
                self.assertIn("timed out", report)
                self.assertNotIn(secret, report)
                window.close()


if __name__ == "__main__":
    unittest.main()
