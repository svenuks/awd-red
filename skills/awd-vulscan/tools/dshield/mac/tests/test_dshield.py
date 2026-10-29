#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dshield  # noqa: E402


WORKSPACE = Path(__file__).resolve().parents[2]
SAMPLE_ROOT = (
    WORKSPACE
    / "src.CRao95"
    / "sample_webroot"
)


class RuleTests(unittest.TestCase):
    def test_load_local_rules(self) -> None:
        db = WORKSPACE / "Modules" / "ws_lib.db"
        self.assertTrue(db.is_file(), db)
        rules = dshield.load_ruleset(db)
        self.assertGreaterEqual(len(rules.signatures), 10_000)
        self.assertGreaterEqual(len(rules.active), 500)
        self.assertIn("正常", rules.categories)


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        db = WORKSPACE / "Modules" / "ws_lib.db"
        cls.rules = dshield.load_ruleset(db) if db.is_file() else None

    def scan(self, name: str, text: str) -> list[dshield.Finding]:
        return dshield.scan_text(name, text, self.rules)

    def test_eval_request_input(self) -> None:
        findings = self.scan(
            "sub.php",
            "<?php $a = $_REQUEST['a']; $b = null; eval($b.$a); ?>",
        )
        self.assertTrue(any(item.level == 5 for item in findings), findings)
        self.assertTrue(any("eval" in item.kind for item in findings), findings)

    def test_assert_through_wrapper(self) -> None:
        findings = self.scan(
            "home.php",
            "<?php function dog($a){ \\assert($a); } dog($_POST[x]); ?>",
        )
        self.assertTrue(any(item.level == 5 for item in findings), findings)
        self.assertTrue(any("assert" in item.kind for item in findings), findings)

    def test_literal_system_command(self) -> None:
        findings = self.scan("user.php", "<?php die(system('whoami')); ?>")
        self.assertTrue(any(item.level >= 3 for item in findings), findings)
        self.assertTrue(any("system" in item.kind for item in findings), findings)

    def test_encoded_eval(self) -> None:
        findings = self.scan(
            "encoded.php",
            "<?php eval(gzinflate(base64_decode($_POST['x']))); ?>",
        )
        self.assertTrue(any(item.level == 5 for item in findings), findings)

    def test_benign_php(self) -> None:
        findings = self.scan(
            "ajax.php",
            """<?php
            if (!defined('ROOT')) die('Access denied.');
            class Ajax {
                public function run() {
                    $value = isset($_GET['callback']) ? $_GET['callback'] : false;
                    echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
                }
            }
            ?>""",
        )
        self.assertFalse([item for item in findings if item.level >= 3], findings)

    def test_dedup_keeps_files_separate(self) -> None:
        first = self.scan("a.php", "<?php system('whoami'); ?>")
        second = self.scan("b.php", "<?php system('kill -9 -1'); ?>")
        combined = dshield.deduplicate_findings(first + second)
        paths = {item.file for item in combined}
        self.assertEqual({"a.php", "b.php"}, paths)

    def test_js_editor_exec_is_not_shell(self) -> None:
        findings = self.scan(
            "plugins/image.js",
            "editor.exec('insertimage', url, title, width, height);",
        )
        self.assertFalse([item for item in findings if item.level >= 3], findings)

    def test_pdo_exec_is_not_shell(self) -> None:
        findings = self.scan(
            "database.php",
            """<?php
            $pdo = new PDO('sqlite::memory:');
            $pdo->exec('DELETE FROM sessions');
            ?>""",
        )
        self.assertFalse([item for item in findings if item.level >= 3], findings)

    def test_validated_upload_is_downgraded(self) -> None:
        findings = self.scan(
            "upload.php",
            """<?php
            $file = $_FILES['file'];
            if (getimagesize($file['tmp_name'])) {
                move_uploaded_file($file['tmp_name'], 'uploads/' . $file['name']);
            }
            ?>""",
        )
        self.assertFalse([item for item in findings if item.level >= 4], findings)

    def test_sample_tree(self) -> None:
        if not SAMPLE_ROOT.is_dir():
            self.skipTest("sample tree is not present")
        expected = {
            "controllers/home.php",
            "controllers/b.php",
            "models/user.php",
            "public/admin/images/sub.php",
        }
        found: set[str] = set()
        high_confidence: set[str] = set()
        for path in dshield.iter_files(
            [SAMPLE_ROOT],
            dshield.SERVER_SCRIPT_EXTENSIONS,
            [],
            8 * 1024 * 1024,
        ):
            file_path, root = path
            findings = dshield.scan_file(
                file_path,
                root,
                self.rules,
                enable_signatures=True,
                enable_heuristics=True,
                max_size=8 * 1024 * 1024,
            )
            if any(item.level >= 3 for item in findings):
                found.add(file_path.relative_to(root).as_posix())
            if any(item.level >= 4 for item in findings):
                high_confidence.add(file_path.relative_to(root).as_posix())
        self.assertTrue(expected.issubset(found), (expected - found, sorted(found)))
        self.assertTrue(
            expected.issubset(high_confidence),
            (expected - high_confidence, sorted(high_confidence)),
        )
        # A legitimate template engine can still contain a dangerous /e
        # preg_replace pattern.  It is reported at level 3, not as a
        # high-confidence webshell.
        self.assertNotIn("system/plugins/STpl.class.php", high_confidence)


if __name__ == "__main__":
    unittest.main()
