"""Inventory enabled custom Wazuh rules; never deploy or prune content."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, quote
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

from daclog import info, error


class FetchError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self, url, username=None, password=None, token=None, ca=None, insecure=False):
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise FetchError("API URL must be HTTPS without credentials, query, or fragment")
        self.url = url.rstrip("/")
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context(cafile=ca)
        self.opener = build_opener(HTTPSHandler(context=context), NoRedirect())
        self.token = token
        if not token:
            if not username or not password:
                raise FetchError("provide WAZUH_USERNAME/WAZUH_PASSWORD or WAZUH_TOKEN")
            auth = base64.b64encode(f"{username}:{password}".encode()).decode()
            self.token = self.request("/security/user/authenticate", {"raw": "true"}, raw=True, method="POST", authorization="Basic " + auth).strip()
            if not self.token or any(c.isspace() for c in self.token):
                raise FetchError("authentication returned an invalid token")

    def request(self, endpoint, params=None, raw=False, method="GET", authorization=None):
        req = Request(self.url + endpoint + ("?" + urlencode(params) if params else ""), method=method,
                      headers={"Authorization": authorization or "Bearer " + self.token})
        try:
            with self.opener.open(req, timeout=30) as response:
                content = response.read().decode("utf-8")
        except HTTPError as exc:
            raise FetchError(f"endpoint={endpoint} HTTP {exc.code}") from None
        except (URLError, OSError, UnicodeError, ValueError):
            raise FetchError(f"endpoint={endpoint} connection/TLS or response decoding failed") from None
        if raw:
            if content.lstrip().startswith("{"):
                raise FetchError(f"endpoint={endpoint} expected raw text, received JSON")
            return content
        try:
            doc = json.loads(content)
            data = doc["data"]
            if doc.get("error", 0) != 0 or data.get("total_failed_items", 0) or data.get("failed_items"):
                raise FetchError(f"endpoint={endpoint} API error or partial failure")
            if not isinstance(data, dict):
                raise TypeError()
            return data
        except (ValueError, KeyError, TypeError, AttributeError):
            raise FetchError(f"endpoint={endpoint} unexpected API response") from None

    def items(self, endpoint, **filters):
        offset = 0
        result = []
        while True:
            data = self.request(endpoint, dict(filters, offset=offset, limit=500))
            page = data.get("affected_items")
            total = data.get("total_affected_items")
            if not isinstance(page, list) or not isinstance(total, int) or total < 0 or any(not isinstance(x, dict) for x in page):
                raise FetchError(f"endpoint={endpoint} invalid pagination response")
            result.extend(page)
            offset += len(page)
            if offset >= total:
                return result
            if not page:
                raise FetchError(f"endpoint={endpoint} pagination stopped before total")


def custom(directory):
    return isinstance(directory, str) and directory == "etc/rules"


def normalized_inventory(client, files, rules):
    enabled = {(f["relative_dirname"], f["file"]) for f in files}
    normalized = []
    for rule in rules:
        if (rule.get("relative_dirname"), rule.get("filename")) not in enabled:
            continue
        if rule.get("status") != "enabled":
            continue
        item = {k: rule[k] for k in ("id", "level", "description", "groups", "mitre", "filename", "relative_dirname", "status") if k in rule}
        normalized.append(item)
    normalized.sort(key=lambda r: (r.get("filename", ""), str(r.get("id", "")), json.dumps(r, sort_keys=True)))
    return json.dumps({"client": client, "files": sorted(files, key=lambda f: f["file"]), "rules": normalized}, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def fetch(api, client, root):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", client):
        raise FetchError("invalid client identifier")
    info("wazuh-fetch", "fetching custom rule files", client=client, platform="wazuh")
    files = []
    contents = {}
    for item in api.items("/rules/files", relative_dirname="etc/rules", status="enabled"):
        if not custom(item.get("relative_dirname")) or item.get("status") != "enabled":
            continue
        filename = item.get("filename") or item.get("file")
        if not isinstance(filename, str) or not re.fullmatch(r"[a-zA-Z0-9_-][a-zA-Z0-9_.-]*\.xml", filename):
            raise FetchError("endpoint=/rules/files unsafe or missing custom filename")
        if filename in contents:
            raise FetchError("endpoint=/rules/files duplicate custom filename")
        contents[filename] = api.request("/rules/files/" + quote(filename), {"raw": "true", "relative_dirname": "etc/rules"}, raw=True)
        files.append({"file": filename, "relative_dirname": item["relative_dirname"], "status": item["status"]})
    rules = api.items("/rules", relative_dirname="etc/rules", status="enabled")
    inventory = normalized_inventory(client, files, rules)
    destination = root / "Inventory" / client
    (destination / "Rules").mkdir(parents=True, exist_ok=True)
    (root / "Native" / client).mkdir(parents=True, exist_ok=True)
    for filename, content in sorted(contents.items()):
        (destination / "Rules" / filename).write_text(content.replace("\r\n", "\n").replace("\r", "\n"), encoding="utf-8", newline="\n")
    (destination / "inventory.json").write_text(inventory, encoding="utf-8", newline="\n")
    info("wazuh-fetch", "inventory fetched; existing files were not pruned", client=client, files=len(files), platform="wazuh")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True)
    parser.add_argument("--api-url", default=os.getenv("WAZUH_API_URL"))
    parser.add_argument("--username", default=os.getenv("WAZUH_USERNAME"))
    parser.add_argument("--ca", default=os.getenv("WAZUH_CA"))
    parser.add_argument("--insecure", action="store_true", help="explicit opt-in for testing with unverified TLS")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        if not args.api_url:
            raise FetchError("provide WAZUH_API_URL or --api-url")
        api = API(args.api_url, args.username, os.getenv("WAZUH_PASSWORD"), os.getenv("WAZUH_TOKEN"), args.ca, args.insecure)
        fetch(api, args.client, args.output)
        return 0
    except (FetchError, OSError) as exc:
        message = str(exc) if isinstance(exc, FetchError) else "local inventory write or CA read failed"
        error("wazuh-fetch", message, client=args.client, platform="wazuh")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
