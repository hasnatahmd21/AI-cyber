from pathlib import Path
from tools.real_dataset_readiness import inspect

def test_real_dataset_readiness(tmp_path: Path):
    (tmp_path/"records.jsonl").write_text('{"id":"fixture"}\n',encoding="utf-8")
    result=inspect(tmp_path)
    assert result["files"]==1
    assert result["bytes"]>0
    assert result["files_detail"][0]["sha256"]
