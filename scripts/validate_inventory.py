"""Validate local custom-rule inventory metadata and XML file references."""
import json
from pathlib import Path
import re

from daclog import error, info

STAGE = "wazuh-inventory-validate"
INVENTORY_ROOT = Path(__file__).resolve().parents[1] / "Inventory"


def validate_client(client):
    path = client / "inventory.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ["inventory.json cannot be read as UTF-8 JSON"]
    if not isinstance(document, dict):
        return ["inventory.json must contain an object"]
    errors = []
    if document.get("client") != client.name:
        errors.append("inventory client identifier must match its directory")
    for collection in ("files", "rules"):
        entries = document.get(collection)
        if not isinstance(entries, list):
            errors.append(f"{collection} must be a list")
            continue
        for index, item in enumerate(entries):
            label = f"{collection}[{index}]"
            if not isinstance(item, dict):
                errors.append(f"{label}: entry must be an object")
                continue
            if item.get("status") != "enabled":
                errors.append(f"{label}: status must be enabled")
            for key in ("relative_dirname", "source_directory", "source_dir"):
                if key in item and item[key] != "etc/rules":
                    errors.append(f"{label}: {key} must be etc/rules (custom content only)")
            references = [item[key] for key in ("filename", "file") if key in item]
            if collection == "files" and not references:
                errors.append(f"{label}: rule filename is required")
            for filename in references:
                if not isinstance(filename, str) or not re.fullmatch(r"[a-zA-Z0-9_-][a-zA-Z0-9_.-]*\.xml", filename):
                    errors.append(f"{label}: unsafe rule filename")
                    continue
                raw = client / "Rules" / filename
                if not raw.is_file() or raw.resolve().parent != (client / "Rules").resolve():
                    errors.append(f"{label}: referenced XML file missing or outside Rules/: {filename}")
    return errors


def validate_inventory(root=INVENTORY_ROOT):
    failed = False
    if not root.exists():
        info(STAGE, "no client inventories configured")
        return 0
    for client in sorted(root.iterdir()):
        if client.name == ".gitkeep" or not client.is_dir():
            continue
        if not (client / "inventory.json").exists():
            info(STAGE, "no inventory.json; client not onboarded", client=client.name)
            continue
        errors = validate_client(client)
        for message in errors:
            error(STAGE, message, client=client.name)
        if errors:
            failed = True
        else:
            info(STAGE, "inventory valid", client=client.name)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(validate_inventory())
