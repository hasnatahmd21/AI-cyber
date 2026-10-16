import gzip
import json
from pathlib import Path

from ai_cyber_os.knowledge import iter_records


def test_gzipped_jsonl_is_read_as_streamed_records(tmp_path: Path):
    path = tmp_path / "cpe-sample.jsonl.gz"
    rows = [
        {"id": "cpe:2.3:a:vendor:one:1.0:*:*:*:*:*:*:*", "title": "one"},
        {"id": "cpe:2.3:a:vendor:two:2.0:*:*:*:*:*:*:*", "title": "two"},
    ]
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")

    records = list(iter_records(path, dataset="cpe", source="fixture"))
    assert len(records) == 2
    assert records[0]["dataset"] == "cpe"
    assert "vendor:one" in json.dumps(records[0], sort_keys=True)
    assert "vendor:two" in json.dumps(records[1], sort_keys=True)


def test_gzipped_csv_stream_skips_comment_lines(tmp_path: Path):
    path = tmp_path / "epss-sample.csv.gz"
    with gzip.open(path, "wt", encoding="utf-8", newline="") as handle:
        handle.write("# generated fixture\n")
        handle.write("cve,epss,percentile\n")
        handle.write("CVE-2025-0001,0.25,0.90\n")
        handle.write("CVE-2025-0002,0.75,0.99\n")

    records = list(iter_records(path, dataset="epss", source="fixture"))
    assert len(records) == 2
    assert records[0]["dataset"] == "epss"
    assert "CVE-2025-0001" in json.dumps(records[0], sort_keys=True)
    assert "CVE-2025-0002" in json.dumps(records[1], sort_keys=True)
