import argparse
import json
from datetime import datetime
from pathlib import Path


def parse_event_time(value: str):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def format_duration(start: datetime, end: datetime) -> str:
    return str(end - start)


def build_metadata(log_path: Path) -> tuple[str, str]:
    data = json.loads(log_path.read_text(encoding="utf-8"))
    events = data.get("activityList", []) if isinstance(data, dict) else data

    event_times = [
        parsed for parsed in (parse_event_time(e.get("time", "")) for e in events)
        if parsed is not None
    ]
    if not event_times:
        return "", ""

    start = min(event_times)
    end = max(event_times)
    return start.isoformat().replace("+00:00", "Z"), format_duration(start, end)


def upsert_category(items: list, category: str, description: str, text: str) -> None:
    payload = {
        "category": category,
        "description": description,
        "items": {"text": text},
    }

    for index, item in enumerate(items):
        if item.get("category") == category:
            items[index] = payload
            return

    items.append(payload)


def process_file(analyzed_path: Path, logs_dir: Path) -> bool:
    stem = analyzed_path.stem
    log_name = stem.removeprefix("analyzed_") + ".json"
    log_path = logs_dir / log_name

    if not log_path.exists():
        print(f"Atlandı: eşleşen log bulunamadı -> {analyzed_path.name}")
        return False

    session_start, session_duration = build_metadata(log_path)
    analyzed_data = json.loads(analyzed_path.read_text(encoding="utf-8"))

    if not isinstance(analyzed_data, list):
        print(f"Atlandı: beklenmeyen analiz formatı -> {analyzed_path.name}")
        return False

    upsert_category(
        analyzed_data,
        "Session Start",
        "Session start timestamp from source log",
        session_start,
    )
    upsert_category(
        analyzed_data,
        "Session Duration",
        "Session duration calculated from first and last event timestamps",
        session_duration,
    )

    analyzed_path.write_text(
        json.dumps(analyzed_data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Güncellendi: {analyzed_path.name}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Analyzed JSON dosyalarına session metadata ekler."
    )
    parser.add_argument(
        "--analyzed-dir",
        required=True,
        help="Analiz edilmiş JSON dosyalarının bulunduğu klasör",
    )
    parser.add_argument(
        "--logs-dir",
        default="./logs",
        help="Orijinal log JSON dosyalarının bulunduğu klasör",
    )
    args = parser.parse_args()

    analyzed_dir = Path(args.analyzed_dir)
    logs_dir = Path(args.logs_dir)

    if not analyzed_dir.is_dir():
        raise SystemExit(f"Analiz klasörü bulunamadı: {analyzed_dir}")
    if not logs_dir.is_dir():
        raise SystemExit(f"Log klasörü bulunamadı: {logs_dir}")

    files = sorted(analyzed_dir.glob("*.json"))
    if not files:
        raise SystemExit(f"JSON dosyası bulunamadı: {analyzed_dir}")

    updated = 0
    for analyzed_file in files:
        if process_file(analyzed_file, logs_dir):
            updated += 1

    print(f"Tamamlandı. Güncellenen dosya sayısı: {updated}")


if __name__ == "__main__":
    main()
