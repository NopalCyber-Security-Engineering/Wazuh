import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from validate_inventory import validate_client, validate_inventory


class InventoryValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "Inventory"
        self.client = self.root / "arbitrary-customer"
        (self.client / "Rules").mkdir(parents=True)
        (self.client / "Rules/local_rules.xml").write_text(
            '<group name="custom"><rule id="100001" level="3"><description>password token</description></rule></group>', encoding="utf-8")
        self.document = {
            "client": self.client.name,
            "files": [{"file": "local_rules.xml", "relative_dirname": "etc/rules", "status": "enabled"}],
            "rules": [{"id": 100001, "filename": "local_rules.xml", "relative_dirname": "etc/rules", "status": "enabled"}],
        }

    def write_inventory(self):
        (self.client / "inventory.json").write_text(json.dumps(self.document), encoding="utf-8")

    def test_enabled_custom_inventory_passes_without_word_scanning(self):
        self.write_inventory()
        self.assertEqual([], validate_client(self.client))

    def test_disabled_or_missing_status_rejected(self):
        for collection in ("files", "rules"):
            for status in ("disabled", None):
                with self.subTest(collection=collection, status=status):
                    self.document[collection][0]["status"] = status
                    self.write_inventory()
                    self.assertTrue(any("status must be enabled" in message for message in validate_client(self.client)))
            self.document[collection][0]["status"] = "enabled"

    def test_builtin_directories_rejected(self):
        for key in ("relative_dirname", "source_directory", "source_dir"):
            with self.subTest(key=key):
                self.document["rules"][0][key] = "ruleset/rules"
                self.write_inventory()
                self.assertTrue(any(f"{key} must be etc/rules" in message for message in validate_client(self.client)))
                del self.document["rules"][0][key]

    def test_optional_source_directory_can_be_absent(self):
        for item in (self.document["files"][0], self.document["rules"][0]):
            del item["relative_dirname"]
        self.write_inventory()
        self.assertEqual([], validate_client(self.client))

    def test_unsafe_filename_rejected(self):
        for filename in ("../outside.xml", "subdir/rule.xml", "subdir\\rule.xml", "/rule.xml", "C:rule.xml", "rule.txt", None):
            with self.subTest(filename=filename):
                self.document["rules"][0]["filename"] = filename
                self.write_inventory()
                self.assertTrue(any("unsafe rule filename" in message for message in validate_client(self.client)))

    def test_missing_xml_rejected(self):
        self.document["files"][0]["file"] = "missing.xml"
        self.write_inventory()
        self.assertTrue(any("referenced XML file missing" in message for message in validate_client(self.client)))

    def test_malformed_json_and_collections_rejected(self):
        path = self.client / "inventory.json"
        path.write_text("{", encoding="utf-8")
        self.assertTrue(validate_client(self.client))
        for value in ([], {"client": self.client.name}, dict(self.document, rules=[None])):
            path.write_text(json.dumps(value), encoding="utf-8")
            self.assertTrue(validate_client(self.client))

    def test_dynamic_clients_skips_unonboarded_and_logs_errors(self):
        (self.root / ".gitkeep").touch()
        (self.root / "not-onboarded/Rules").mkdir(parents=True)
        self.write_inventory()
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(0, validate_inventory(self.root))
        self.assertIn("client=not-onboarded", stdout.getvalue())
        self.document["rules"][0]["status"] = "disabled"
        self.write_inventory()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(1, validate_inventory(self.root))
        self.assertIn("DAC | ERROR | stage=wazuh-inventory-validate | client=arbitrary-customer", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
