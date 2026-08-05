from pathlib import Path


def write_result(results_dir: Path, name: str, value: str) -> None:
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / name).write_text(value)
    print(value)
