"""
PAM Log Analyzer v3 — Full LLM Pipeline
=========================================
Tüm sınıflandırma Qwen modeline bırakılır.
Komut düzeltme, IDE terminali tanıma, random metin ayıklama — hepsi LLM'de.

Gereksinimler:
  pip install openai
  Ollama çalışıyor olmalı: ollama serve
  Model indirilmiş olmalı: ollama pull ministral-3:14b

Kullanım:
  python profil_maker_ministral.py --input /path/to/logs --output /path/to/output
  python profil_maker_ministral.py --input /path/to/logs --output /path/to/output --model ministral-3:14b
"""

import json
import os
import sys
import argparse
import time
from pathlib import Path
from openai import OpenAI

# ============================================================
# SYSTEM PROMPT — Qwen'e ne yapması gerektiğini anlatır
# ============================================================

SYSTEM_PROMPT = """You are analyzing PAM (Privileged Access Management) session activity logs from a Windows machine.
You receive a JSON array of chronological events. Each event has an "eventInfo" field.
Your job: extract three lists from the session.
1. **urls** — Real websites the user visited (from browser window titles). Skip browser chrome like New Tab, History, search result pages, error pages.
2. **commands** — Shell commands the user actually executed in a terminal. This means commands typed at a command prompt and run — like "python script.py", "git status", "ping 10.0.0.1", "dir", "whoami". Use your judgment to distinguish real executed commands from everything else: source code being written or pasted, values typed into a running program, text typed in browsers or chat windows, file rename operations, search queries, and keyboard noise. Fix obvious typos from non-English keyboards.Skip the code that belongs to a specific programming language. Only include the commands that belong to a specific application or system.
3. **apps** — Desktop applications that were actively used. Use clean names (e.g. "Command Prompt" not "cmd.exe, Administrator: Command Prompt"). Include terminal apps here too. Skip desktop background (Program Manager), OS search, and window close events.
Respond with ONLY valid JSON, nothing else:
{"urls":{"name":count},"commands":{"command":count},"apps":{"name":count},"summary":"One sentence English summary."}
"""

# ============================================================
# LLM CLIENT
# ============================================================

def create_client(api_base: str) -> OpenAI:
    return OpenAI(base_url=api_base, api_key="not-needed")


def classify_with_llm(
    client: OpenAI,
    events: list[dict],
    model: str,
    max_retries: int = 3,
) -> dict:
    """
    Event listesini LLM'e gönder, sınıflandırılmış JSON al.
    """
    def normalize_counter_map(value) -> dict:
        """LLM bazen dict yerine list döndürebilir; güvenli şekilde normalize et."""
        if isinstance(value, dict):
            normalized = {}
            for k, v in value.items():
                key = str(k).strip()
                if not key:
                    continue
                try:
                    normalized[key] = int(v)
                except Exception:
                    try:
                        normalized[key] = int(float(v))
                    except Exception:
                        continue
            return normalized

        if isinstance(value, list):
            normalized = {}
            for item in value:
                if isinstance(item, str):
                    key = item.strip()
                    if key:
                        normalized[key] = normalized.get(key, 0) + 1
                elif isinstance(item, dict):
                    key = str(
                        item.get("name")
                        or item.get("label")
                        or item.get("item")
                        or item.get("command")
                        or item.get("app")
                        or item.get("url")
                        or ""
                    ).strip()
                    if not key:
                        continue
                    raw_count = item.get("count", 1)
                    try:
                        count = int(raw_count)
                    except Exception:
                        try:
                            count = int(float(raw_count))
                        except Exception:
                            count = 1
                    normalized[key] = normalized.get(key, 0) + count
            return normalized

        return {}

    # ===========================================================
    # PRE-PROCESSING: Kesin gürültüyü LLM'e göndermeden temizle
    # ===========================================================
    def preprocess_events(raw_events: list[dict]) -> list[dict]:
        """
        LLM'in işini kolaylaştır:
        - Shortcut ve Paste event'lerini kaldır
        - Multi-line Entry'leri kaldır (yapıştırılan kod blokları)
        - Çalışan programa girilen tek sayı/kelime input'ları kaldır
        - Window Closed / SESSION_CLOSED kaldır
        - Program Manager tekrarlarını azalt
        """
        import re
        cleaned = []
        prev_was_terminal = False
        
        for e in raw_events:
            info = e.get("eventInfo", "").strip()
            
            # 1. Skip: Shortcut, Paste events
            if "Shortcut used:" in info or "Paste detected." in info:
                continue
            
            # 2. Skip: Window Closed, SESSION_CLOSED
            if info in ("(Window Closed)", "SESSION_CLOSED"):
                continue
            
            # 3. Skip: Multi-line Entry (contains \r\n) = pasted code
            if "Entry:" in info and ("\\r\\n" in info or "\r\n" in info):
                continue
            
            # 4. Track terminal context for input filtering
            lower = info.lower()
            is_terminal = any(t in lower for t in [
                "cmd.exe", "powershell", "command prompt",
                "c:\\windows\\system32\\cmd.exe"
            ])
            
            # 5. Skip: Single number/short word Entry in terminal = program input
            entry_match = re.search(r"Entry:\s*(.+)$", info)
            if entry_match and prev_was_terminal:
                entry_text = entry_match.group(1).strip()
                # Pure number or very short (1-2 chars) = program input
                if re.match(r"^\d+$", entry_text) or len(entry_text) <= 2:
                    continue
            
            if is_terminal:
                prev_was_terminal = True
            elif not ("Entry:" in info):
                # Non-entry, non-terminal event resets context
                prev_was_terminal = is_terminal
            
            cleaned.append(e)
        
        return cleaned
    
    filtered_events = preprocess_events(events)
    
    # Sadece eventInfo gönder (token tasarrufu)
    slim_events = []
    for e in filtered_events:
        slim_events.append({
            "eventInfo": e.get("eventInfo", ""),
        })

    user_content = json.dumps(slim_events, ensure_ascii=False)

    for attempt in range(max_retries):
        try:
            # Qwen3 modeller için /no_think ekle (thinking kapatır)
            # Diğer modellerde etkisiz olur
            actual_prompt = user_content + "\n/no_think"

            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": actual_prompt},
                ],
                temperature=0.1,  # Deterministic olsun
                max_tokens=4000,
            )

            raw = response.choices[0].message.content.strip()

            # Qwen3 thinking tags temizle
            if "<think>" in raw:
                import re
                raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()

            # Markdown backtick temizle
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
            if raw.endswith("```"):
                raw = raw[:-3]
            raw = raw.replace("```json", "").replace("```", "").strip()

            # JSON bloğunu bul (bazen LLM'in ekstra metin eklediği durumlar)
            json_start = raw.find("{")
            json_end = raw.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                raw = raw[json_start:json_end]

            parsed = json.loads(raw)

            # Validate structure
            result = {
                "urls": normalize_counter_map(parsed.get("urls", {})),
                "commands": normalize_counter_map(parsed.get("commands", {})),
                "apps": normalize_counter_map(parsed.get("apps", {})),
                "summary": str(parsed.get("summary", "")).strip(),
            }

            return result

        except json.JSONDecodeError as e:
            print(f"  ⚠ JSON parse hatası (deneme {attempt + 1}/{max_retries}): {e}")
            print(f"    Ham yanıt (ilk 500 kar): {raw[:500]}")
            if attempt < max_retries - 1:
                time.sleep(1)
        except Exception as e:
            print(f"  ⚠ LLM hatası (deneme {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(2)

    print("  ❌ LLM sınıflandırma başarısız oldu, boş sonuç dönülüyor.")
    return {"urls": {}, "commands": {}, "apps": {}, "summary": ""}


# ============================================================
# BATCH PROCESSING (büyük dosyalar için)
# ============================================================

def classify_large_session(
    client: OpenAI,
    events: list[dict],
    model: str,
    batch_size: int = 80,
) -> dict:
    """
    Büyük session'ları batch'lere bölerek işle.
    Qwen 1.5B context window'u küçük olduğu için 80 event'lik parçalar.
    """
    if len(events) <= batch_size:
        return classify_with_llm(client, events, model)

    # Batch'lere böl
    merged = {"urls": {}, "commands": {}, "apps": {}}

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (len(events) + batch_size - 1) // batch_size
        print(f"    Batch {batch_num}/{total_batches} ({len(batch)} event)...")

        result = classify_with_llm(client, batch, model)

        # Merge
        for category in merged:
            for key, count in result.get(category, {}).items():
                merged[category][key] = merged[category].get(key, 0) + count

    return merged


# ============================================================
# OUTPUT BUILDER
# ============================================================

def build_output_json(results: dict) -> list:
    """Standart çıktı formatı."""
    # Count'a göre sırala
    def sorted_dict(d):
        return dict(sorted(d.items(), key=lambda x: x[1], reverse=True))

    return [
        {
            "category": "URLs",
            "description": "Ziyaret edilen web sayfaları",
            "items": sorted_dict(results["urls"]),
        },
        {
            "category": "Commands",
            "description": "Çalıştırılan terminal komutları",
            "items": sorted_dict(results["commands"]),
        },
        {
            "category": "Applications",
            "description": "Kullanılan uygulamalar",
            "items": sorted_dict(results["apps"]),
        },
        {
            "category": "Summary",
            "description": "One-sentence English session summary",
            "items": {
                "text": results.get("summary", ""),
            },
        },
    ]


# ============================================================
# FILE PROCESSOR
# ============================================================

def process_file(
    client: OpenAI,
    input_path: str,
    output_path: str,
    model: str,
):
    """Tek bir JSON dosyasını işle."""
    print(f"  📄 {os.path.basename(input_path)} okunuyor...")

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        events = data
    elif isinstance(data, dict) and isinstance(data.get("activityList"), list):
        events = data["activityList"]
    else:
        print(f"  ⚠ Geçersiz format (list veya activityList bekleniyor)")
        return

    print(f"    {len(events)} event bulundu, LLM'e gönderiliyor...")
    start = time.time()

    results = classify_large_session(client, events, model)

    elapsed = time.time() - start
    output = build_output_json(results)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    total_urls = sum(results["urls"].values())
    total_cmds = sum(results["commands"].values())
    total_apps = sum(results["apps"].values())

    print(f"  ✓ → {os.path.basename(output_path)} ({elapsed:.1f}s)")
    print(f"    {total_urls} URL, {total_cmds} komut, {total_apps} uygulama")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="PAM Log Analyzer v3 — Full LLM Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  # Varsayılan (Ministral 3 14B, Ollama)
  python profil_maker_ministral.py --input ./logs --output ./analyzed

  # Farklı model
  python profil_maker_ministral.py --input ./logs --output ./analyzed --model ministral-3:14b

  # Farklı endpoint (LM Studio, vLLM vb.)
  python profil_maker_ministral.py --input ./logs --output ./analyzed --endpoint http://localhost:1234/v1

  # Tek dosya
  python profil_maker_ministral.py --input ./logs/session1.json --output ./analyzed
        """,
    )
    parser.add_argument("--input", "-i", required=True, help="JSON dosyası veya klasör")
    parser.add_argument("--output", "-o", required=True, help="Çıktı klasörü")
    parser.add_argument("--endpoint", "-e", default="http://localhost:11434/v1",
                        help="OpenAI-compatible API endpoint (varsayılan: Ollama)")
    parser.add_argument("--model", "-m", default="ministral-3:14b",
                        help="Model adı (varsayılan: ministral-3:14b)")
    parser.add_argument("--batch-size", "-b", type=int, default=80,
                        help="Batch başına event sayısı (varsayılan: 80)")
    args = parser.parse_args()

    # Dosyaları bul
    input_path = Path(args.input)
    if input_path.is_file():
        files = [input_path]
    elif input_path.is_dir():
        files = sorted(input_path.glob("*.json"))
    else:
        print(f"❌ Bulunamadı: {args.input}")
        sys.exit(1)

    if not files:
        print(f"❌ JSON dosyası bulunamadı: {args.input}")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    # Client oluştur
    print(f"🔗 Endpoint: {args.endpoint}")
    print(f"🤖 Model: {args.model}")
    print(f"📂 {len(files)} dosya bulundu.\n")

    client = create_client(args.endpoint)

    # Her dosyayı işle
    total_start = time.time()
    for f in files:
        out_name = f"analyzed_{f.stem}.json"
        out_path = os.path.join(args.output, out_name)
        if os.path.exists(out_path):
            print(f"⏭ Atlanıyor: {out_name} zaten mevcut")
            print()
            continue
        process_file(client, str(f), out_path, args.model)
        print()

    total_elapsed = time.time() - total_start
    print(f"✅ Tamamlandı! Toplam süre: {total_elapsed:.1f}s")


if __name__ == "__main__":
    main()
