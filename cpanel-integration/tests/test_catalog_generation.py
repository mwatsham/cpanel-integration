import hashlib
import json
from pathlib import Path


def test_pinned_openapi_matches_lock() -> None:
    root = Path(__file__).parents[1]
    source = root / "specifications" / "cpanel.openapi.json"
    lock = json.loads((root / "specifications" / "cpanel.openapi.lock.json").read_text())
    assert hashlib.sha256(source.read_bytes()).hexdigest() == lock["sha256"]
    document = json.loads(source.read_text())
    assert document["openapi"] == "3.0.2"
    assert document["info"]["version"] == "11.136.0.25"
    assert len(document["paths"]) == 605
