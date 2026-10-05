import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from fetch_custom_rules import API, FetchError, fetch, normalized_inventory


class FetchTests(unittest.TestCase):
    def test_filters_custom_enabled_files_and_metadata(self):
        files = [{"filename": name, "relative_dirname": directory, "status": status} for name, directory, status in (
            ("local_rules.xml", "etc/rules", "enabled"), ("disabled.xml", "etc/rules", "disabled"), ("vendor.xml", "ruleset/rules", "enabled"))]
        rules = [{"id": index, "filename": f["filename"], "relative_dirname": f["relative_dirname"], "description": "Rule", "status": f["status"]} for index, f in enumerate(files)]
        api = Mock()
        api.items.side_effect = [files, rules]
        api.request.return_value = '<group name="custom"><rule id="0" level="3"/></group>\r\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fetch(api, "customer-new", root)
            destination = root / "Inventory/customer-new"
            self.assertEqual(["local_rules.xml"], [p.name for p in (destination / "Rules").iterdir()])
            self.assertEqual([0], [r["id"] for r in json.loads((destination / "inventory.json").read_text())["rules"]])
            self.assertNotIn(b"\r", (destination / "Rules/local_rules.xml").read_bytes())
            api.request.assert_called_once_with(
                "/rules/files/local_rules.xml",
                {"raw": "true", "relative_dirname": "etc/rules"},
                raw=True,
            )

    def test_pagination(self):
        api = API("https://example.test:55000", token="test")
        api.request = Mock(side_effect=[{"affected_items": [{"id": 1}], "total_affected_items": 2}, {"affected_items": [{"id": 2}], "total_affected_items": 2}])
        self.assertEqual([{"id": 1}, {"id": 2}], api.items("/rules"))
        self.assertEqual(1, api.request.call_args.args[1]["offset"])

    def test_empty_page_before_total_fails(self):
        api = API("https://example.test", token="test")
        api.request = Mock(return_value={"affected_items": [], "total_affected_items": 1})
        with self.assertRaises(FetchError):
            api.items("/rules")

    def test_deterministic_inventory(self):
        files = [{"file": "local.xml", "relative_dirname": "etc/rules", "status": "enabled"}]
        rules = [{"id": i, "filename": "local.xml", "relative_dirname": "etc/rules", "status": "enabled"} for i in (2, 1)]
        self.assertEqual(normalized_inventory("client", files, rules), normalized_inventory("client", files, list(reversed(rules))))

    def test_failure_does_not_modify_existing_inventory(self):
        api = Mock()
        api.items.side_effect = FetchError("HTTP 401")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "Inventory/client/Rules/local.xml"
            file.parent.mkdir(parents=True)
            file.write_text("existing")
            with self.assertRaises(FetchError):
                fetch(api, "client", root)
            self.assertEqual("existing", file.read_text())

    def test_http_error_hides_response_and_credentials(self):
        api = API("https://example.test", token="SECRET")
        api.opener = Mock()
        api.opener.open.side_effect = HTTPError("https://example.test", 401, "SECRET", {}, None)
        with self.assertRaisesRegex(FetchError, "endpoint=/rules/files HTTP 401") as caught:
            api.request("/rules/files")
        self.assertNotIn("SECRET", str(caught.exception))

    def test_authentication_and_tls_defaults(self):
        from unittest.mock import patch
        with patch.object(API, "request", return_value="jwt") as request:
            api = API("https://example.test", "user", "password")
            self.assertEqual("jwt", api.token)
            self.assertEqual("POST", request.call_args.kwargs["method"])


if __name__ == "__main__":
    unittest.main()
