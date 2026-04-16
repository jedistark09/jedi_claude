"""
Anomaly Detector â€” PAM UBA Pipeline
=====================================
Yeni bir session'i chunk profilleri ve genel profil ile karsilastirir.
Python deterministik flag'ler uretir, LLM (Mistral/Qwen) yorumlar.

Kullanim:
  python anomaly_detector.py \
    --session ./analyzed/analyzed_xxx.json \
    --profile ./profiles/profile.json \
    --chunks  ./profiles/ \
    --model   mistral-small3.1 \
    --endpoint http://localhost:11434/v1
"""

import json, os, sys, re, argparse, math, time
from pathlib import Path
from openai import OpenAI


# ============================================================
# SESSION PARSER (ayni format profile_builder ile)
# ============================================================

def parse_session(filepath: str) -> dict | None:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        return None

    session = {
        "sessionId": Path(filepath).stem.replace("analyzed_", ""),
        "timestamp": "", "duration": 0,
        "urls": [], "commands": [], "apps": [], "summary": "",
    }
    for block in data:
        cat = block.get("category", "")
        items = block.get("items", {})
        if cat == "URLs":
            session["urls"] = list(items.keys())
        elif cat == "Commands":
            session["commands"] = [c for c, n in items.items() if n > 0]
        elif cat == "Applications":
            session["apps"] = [a for a, n in items.items() if n > 0]
        elif cat == "Summary":
            session["summary"] = items.get("text", "")
        elif cat == "Session Start":
            session["timestamp"] = items.get("text", "")
        elif cat == "Session Duration":
            session["duration"] = _parse_dur(items.get("text", "0:00:00"))
    return session if session["timestamp"] else None


def _parse_dur(s: str) -> int:
    try:
        p = s.split(":")
        if len(p) == 3: return int(p[0])*3600 + int(p[1])*60 + int(p[2])
        if len(p) == 2: return int(p[0])*60 + int(p[1])
    except: pass
    return 0


def _extract_ips(commands: list[str]) -> set[str]:
    pat = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    return {m for cmd in commands for m in pat.findall(cmd)}


def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    avg = sum(values) / len(values)
    variance = sum((x - avg) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


# ============================================================
# PYTHON FLAG ENGINE (deterministik)
# ============================================================

def detect_flags(session: dict, profile: dict, config: dict = None) -> list[dict]:
    """
    Session'i profile ile karsilastir, anomali flag listesi dondur.
    Her flag: {type, detail, items?, severity_hint}
    """
    if config is None:
        config = {
            "spike_threshold": 2.0,       # ortalamadan kac kat fazla = spike
            "duration_spike": 3.0,        # session suresi kac kat fazla
            "off_hours_severity": "medium",
        }

    flags = []

    # --- 1. Yeni komutlar (profilde hic gorulmemis) ---
    known_cmds = set(profile.get("commandFrequency", {}).keys())
    session_cmds = set(session["commands"])
    new_cmds = session_cmds - known_cmds
    if new_cmds:
        flags.append({
            "type": "new_commands",
            "detail": f"{len(new_cmds)} command(s) never seen in profile",
            "items": sorted(new_cmds),
            "severity_hint": "high" if len(new_cmds) >= 3 else "medium",
        })

    # --- 2. Yeni uygulamalar ---
    known_apps = set(profile.get("appFrequency", {}).keys())
    session_apps = set(session["apps"])
    new_apps = session_apps - known_apps
    if new_apps:
        flags.append({
            "type": "new_applications",
            "detail": f"{len(new_apps)} application(s) never seen in profile",
            "items": sorted(new_apps),
            "severity_hint": "high" if len(new_apps) >= 2 else "medium",
        })

    # --- 3. Yeni URL'ler ---
    known_urls = set(profile.get("urlFrequency", {}).keys())
    session_urls = set(session["urls"])
    new_urls = session_urls - known_urls
    if new_urls:
        flags.append({
            "type": "new_urls",
            "detail": f"{len(new_urls)} website(s) never seen in profile",
            "items": sorted(new_urls),
            "severity_hint": "low",
        })

    # --- 4. Saat kontrolu ---
    ah = profile.get("activeHours", {})
    range_start = ah.get("rangeStart", 0)
    range_end = ah.get("rangeEnd", 23)
    try:
        session_hour = int(session["timestamp"][11:13])
        if session_hour < range_start or session_hour > range_end:
            flags.append({
                "type": "off_hours",
                "detail": f"Session at {session_hour:02d}:00, normal range {range_start:02d}:00-{range_end:02d}:59",
                "severity_hint": config["off_hours_severity"],
            })
    except (ValueError, IndexError):
        pass

    # --- 5. Komut sayisi spike ---
    avg_cmds = profile.get("avgCommandsPerSession", 0)
    cmds_history = profile.get("commandsPerSession", [])
    session_cmd_count = len(session["commands"])

    if avg_cmds > 0 and session_cmd_count > 0:
        ratio = session_cmd_count / avg_cmds
        if ratio >= config["spike_threshold"]:
            std = _stddev([float(x) for x in cmds_history]) if cmds_history else 0
            flags.append({
                "type": "command_count_spike",
                "detail": f"{session_cmd_count} commands vs avg {avg_cmds} ({ratio:.1f}x), stddev={std:.1f}",
                "severity_hint": "high" if ratio >= 3.0 else "medium",
            })

    # --- 6. Session suresi spike ---
    avg_dur = profile.get("avgSessionDuration", 0)
    if avg_dur > 0 and session["duration"] > 0:
        dur_ratio = session["duration"] / avg_dur
        if dur_ratio >= config["duration_spike"]:
            flags.append({
                "type": "duration_spike",
                "detail": f"{session['duration']}s vs avg {avg_dur}s ({dur_ratio:.1f}x)",
                "severity_hint": "medium",
            })

    # --- 7. Yeni hedef IP'ler ---
    known_ips = set(profile.get("knownTargetIPs", []))
    session_ips = _extract_ips(session["commands"])
    new_ips = session_ips - known_ips
    if new_ips:
        flags.append({
            "type": "new_target_ips",
            "detail": f"{len(new_ips)} IP(s) never seen before",
            "items": sorted(new_ips),
            "severity_hint": "high",
        })

    # --- 8. Chunk trend karsilastirma ---
    # (chunks varsa en son chunk ile kiyasla)

    return flags


# ============================================================
# CHUNK COMPARISON
# ============================================================

def compare_with_chunks(session: dict, chunks: list[dict]) -> list[dict]:
    """Session'i her chunk ile kiyasla, trend flag'leri uret."""
    if not chunks:
        return []

    flags = []
    latest_chunk = chunks[-1]

    # Session'daki komutlar son chunk'ta var mi?
    chunk_cmds = set(latest_chunk.get("commandFrequency", {}).keys())
    session_cmds = set(session["commands"])
    new_vs_chunk = session_cmds - chunk_cmds

    if new_vs_chunk and len(new_vs_chunk) >= 2:
        flags.append({
            "type": "new_vs_latest_chunk",
            "detail": f"{len(new_vs_chunk)} commands not in latest chunk (chunk {latest_chunk.get('chunkIndex', '?')})",
            "items": sorted(new_vs_chunk),
            "severity_hint": "medium",
        })

    # Komut yogunlugu trendi
    chunk_avgs = [c.get("avgCommandsPerSession", 0) for c in chunks]
    session_cmd_count = len(session["commands"])
    if chunk_avgs and session_cmd_count > 0:
        last_avg = chunk_avgs[-1]
        if last_avg > 0 and session_cmd_count / last_avg >= 2.5:
            flags.append({
                "type": "escalation_vs_chunk",
                "detail": f"{session_cmd_count} cmds vs chunk avg {last_avg} ({session_cmd_count/last_avg:.1f}x)",
                "severity_hint": "medium",
            })

    return flags


# ============================================================
# LLM INTERPRETER (Mistral / Qwen)
# ============================================================

LLM_PROMPT = """You are a PAM security analyst. You receive:
1. A user behavior PROFILE summary (baseline from past sessions)
2. A NEW SESSION summary
3. A list of ANOMALY FLAGS detected by automated comparison

Your job: interpret the flags in context and produce a risk assessment.

For each flag, explain WHY it matters from a security perspective.
Consider combinations â€” multiple weak signals together may indicate a serious threat.

Respond ONLY with JSON:
{
  "riskScore": 0-100,
  "verdict": "normal|suspicious|critical",
  "anomalies": [
    {"type": "flag_type", "detail": "your security interpretation", "severity": "low|medium|high|critical"}
  ],
  "reasoning": "One paragraph explaining your overall assessment."
}
"""


def interpret_with_llm(
    session: dict,
    profile: dict,
    flags: list[dict],
    client: OpenAI,
    model: str,
) -> dict:
    """Flag'leri LLM'e gonder, yorumlatip risk skoru al."""

    # Profile ozeti (token tasarrufu icin sadece key istatistikler)
    profile_summary = {
        "totalSessions": profile.get("totalSessions", 0),
        "activeHours": f"{profile['activeHours']['rangeStart']:02d}:00-{profile['activeHours']['rangeEnd']:02d}:59",
        "avgDuration": f"{profile.get('avgSessionDuration', 0)}s",
        "avgCmdsPerSession": profile.get("avgCommandsPerSession", 0),
        "topCommands": list(profile.get("commandFrequency", {}).keys())[:10],
        "topApps": list(profile.get("appFrequency", {}).keys())[:8],
        "topUrls": list(profile.get("urlFrequency", {}).keys())[:8],
        "knownIPs": profile.get("knownTargetIPs", []),
    }

    session_summary = {
        "timestamp": session["timestamp"],
        "duration": f"{session['duration']}s",
        "urls": session["urls"],
        "commands": session["commands"],
        "apps": session["apps"],
    }

    user_content = json.dumps({
        "profile": profile_summary,
        "newSession": session_summary,
        "flags": flags,
    }, ensure_ascii=False, indent=2)

    for attempt in range(3):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": LLM_PROMPT},
                    {"role": "user", "content": user_content + "\n/no_think"},
                ],
                temperature=0,
                max_tokens=2000,
                seed=42,
            )

            raw = resp.choices[0].message.content.strip()

            # Clean thinking tags
            raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
            raw = raw.replace("```json", "").replace("```", "").strip()

            # Extract JSON
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                raw = raw[start:end]

            return json.loads(raw)

        except json.JSONDecodeError as e:
            print(f"  âš  JSON parse error (attempt {attempt+1}/3): {e}")
            print(f"    Raw: {raw[:300]}")
            time.sleep(1)
        except Exception as e:
            print(f"  âš  LLM error (attempt {attempt+1}/3): {e}")
            time.sleep(2)

    return {"riskScore": -1, "verdict": "error", "anomalies": [], "reasoning": "LLM interpretation failed."}


# ============================================================
# OUTPUT
# ============================================================

def build_report(session: dict, flags: list[dict], llm_result: dict | None) -> dict:
    """Anomaly raporu JSON olustur."""
    return {
        "sessionId": session["sessionId"],
        "timestamp": session["timestamp"],
        "duration": session["duration"],
        "session": {
            "urls": session["urls"],
            "commands": session["commands"],
            "apps": session["apps"],
        },
        "pythonFlags": flags,
        "flagCount": len(flags),
        "llmAssessment": llm_result,
        "finalVerdict": llm_result["verdict"] if llm_result else ("normal" if not flags else "needs_review"),
        "finalRiskScore": llm_result["riskScore"] if llm_result else (len(flags) * 15),
    }


def print_report(report: dict):
    v = report["finalVerdict"]
    score = report["finalRiskScore"]
    colors = {"normal": "[OK]", "suspicious": "[WARN]", "critical": "[CRIT]", "needs_review": "[REVIEW]", "error": "[ERROR]"}
    icon = colors.get(v, "[?]")

    print(f"\n{'='*60}")
    print(f"  {icon} ANOMALY REPORT - {report['sessionId'][:12]}...")
    print(f"{'='*60}")
    print(f"  Time:     {report['timestamp']}")
    print(f"  Duration: {report['duration']}s")
    print(f"  Verdict:  {v.upper()}")
    print(f"  Risk:     {score}/100")
    print(f"  Flags:    {report['flagCount']}")

    if report["pythonFlags"]:
        print(f"\n  Python flags:")
        for f in report["pythonFlags"]:
            sev = f.get("severity_hint", "?")
            print(f"    [{sev:6s}] {f['type']}: {f['detail']}")
            if "items" in f:
                print(f"            â†’ {', '.join(f['items'][:5])}")

    llm = report.get("llmAssessment")
    if llm and llm.get("reasoning"):
        print(f"\n  LLM reasoning:")
        # Word wrap
        words = llm["reasoning"].split()
        line = "    "
        for w in words:
            if len(line) + len(w) > 76:
                print(line)
                line = "    "
            line += w + " "
        if line.strip():
            print(line)

    if llm and llm.get("anomalies"):
        print(f"\n  LLM anomalies:")
        for a in llm["anomalies"]:
            sev = a.get("severity", "?")
            print(f"    [{sev:8s}] {a.get('type', '?')}: {a.get('detail', '')}")

    print(f"{'='*60}")


# ============================================================
# RUNNER
# ============================================================

def run_detection(session_path: str, profile: dict, chunks: list[dict], args, client: OpenAI | None = None) -> dict:
    """Tek bir analyzed session dosyasini isleyip rapor dondur."""
    session = parse_session(session_path)
    if not session:
        raise ValueError(f"Invalid session: {session_path}")

    print(f"  [Session] {session['sessionId'][:12]}...")
    print(f"     Time: {session['timestamp']}, Duration: {session['duration']}s")
    print(f"     Commands: {', '.join(session['commands'][:5]) or '(none)'}")
    print(f"     Apps: {', '.join(session['apps'][:5]) or '(none)'}")
    print(f"     URLs: {', '.join(session['urls'][:5]) or '(none)'}")

    config = {
        "spike_threshold": args.spike,
        "duration_spike": args.dur_spike,
        "off_hours_severity": "medium",
    }
    flags = detect_flags(session, profile, config)
    flags.extend(compare_with_chunks(session, chunks))

    print(f"\n  [Flags] Python detected {len(flags)} flag(s)")

    llm_result = None
    if flags and args.model:
        if client is None:
            client = OpenAI(base_url=args.endpoint, api_key="not-needed")
        print(f"  [LLM] Sending to {args.model} for interpretation...")
        t = time.time()
        llm_result = interpret_with_llm(session, profile, flags, client, args.model)
        print(f"  [OK] LLM response in {time.time()-t:.1f}s")
    elif not flags:
        print(f"  [OK] No flags - session is NORMAL (LLM not needed)")
        llm_result = {"riskScore": 0, "verdict": "normal", "anomalies": [], "reasoning": "No anomalies detected."}

    report = build_report(session, flags, llm_result)
    print_report(report)
    return report


# ============================================================
# MAIN
# ============================================================

def main():
    p = argparse.ArgumentParser(
        description="PAM Anomaly Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sadece Python flag'leri (LLM yok, hizli)
  python anomaly_detector.py -s ./analyzed/analyzed_xxx.json -p ./profiles/profile.json

  # Python flags + LLM yorumlama
  python anomaly_detector.py -s ./analyzed/analyzed_xxx.json -p ./profiles/profile.json -c ./profiles/ -m mistral-small3.1

  # Farkli endpoint
  python anomaly_detector.py -s ./session.json -p ./profile.json -m qwen2.5:14b -e http://localhost:11434/v1
        """,
    )
    p.add_argument("--session", "-s", required=True, help="Analyzed session JSON dosyasi")
    p.add_argument("--profile", "-p", required=True, help="Profil JSON dosyasi")
    p.add_argument("--chunks", "-c", default=None, help="Chunk dosyalari klasoru (opsiyonel)")
    p.add_argument("--model", "-m", default=None, help="LLM model adi (None = sadece Python flags)")
    p.add_argument("--endpoint", "-e", default="http://localhost:11434/v1", help="LLM API endpoint")
    p.add_argument("--output", "-o", default=None, help="Rapor cikti dosyasi (opsiyonel)")
    p.add_argument("--spike", type=float, default=2.0, help="Komut spike esigi (default: 2.0x)")
    p.add_argument("--dur-spike", type=float, default=3.0, help="Sure spike esigi (default: 3.0x)")
    args = p.parse_args()

    session_path = Path(args.session)
    if session_path.is_dir():
        with open(args.profile, "r", encoding="utf-8") as f:
            profile = json.load(f)
        print(f"\n  ÄŸÅ¸â€œÅ  Profile: {profile.get('totalSessions', 0)} sessions, "
              f"{profile['activeHours']['rangeStart']:02d}-{profile['activeHours']['rangeEnd']:02d}h")

        chunks = []
        if args.chunks:
            chunk_dir = Path(args.chunks)
            chunk_files = sorted(chunk_dir.glob("chunk_*.json"))
            for cf in chunk_files:
                with open(cf, "r", encoding="utf-8") as f:
                    chunks.append(json.load(f))
            if chunks:
                print(f"  [Chunks] {len(chunks)} chunks loaded")

        files = sorted(session_path.glob("analyzed_*.json"))
        if not files:
            print(f"[ERROR] No analyzed session files found in: {args.session}")
            sys.exit(1)
        if not args.output:
            print("[ERROR] Batch mode requires --output as a target folder")
            sys.exit(1)

        os.makedirs(args.output, exist_ok=True)
        print(f"\n  [Batch] {len(files)} session file(s)")
        client = OpenAI(base_url=args.endpoint, api_key="not-needed") if args.model else None

        for sf in files:
            print(f"\n--- {sf.name} ---")
            report = run_detection(str(sf), profile, chunks, args, client)
            out_path = Path(args.output) / f"report_{sf.stem}.json"
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(f"\n  [Saved] Report saved: {out_path}")
        return

    # --- 1. Session oku ---
    session = parse_session(args.session)
    if not session:
        print(f"[ERROR] Invalid session: {args.session}")
        sys.exit(1)

    print(f"  [Session] {session['sessionId'][:12]}...")
    print(f"     Time: {session['timestamp']}, Duration: {session['duration']}s")
    print(f"     Commands: {', '.join(session['commands'][:5]) or '(none)'}")
    print(f"     Apps: {', '.join(session['apps'][:5]) or '(none)'}")
    print(f"     URLs: {', '.join(session['urls'][:5]) or '(none)'}")

    # --- 2. Profil oku ---
    with open(args.profile, "r", encoding="utf-8") as f:
        profile = json.load(f)
    print(f"\n  ğŸ“Š Profile: {profile.get('totalSessions', 0)} sessions, "
          f"{profile['activeHours']['rangeStart']:02d}-{profile['activeHours']['rangeEnd']:02d}h")

    # --- 3. Chunk'lari oku (varsa) ---
    chunks = []
    if args.chunks:
        chunk_dir = Path(args.chunks)
        chunk_files = sorted(chunk_dir.glob("chunk_*.json"))
        for cf in chunk_files:
            with open(cf, "r", encoding="utf-8") as f:
                chunks.append(json.load(f))
        if chunks:
            print(f"  [Chunks] {len(chunks)} chunks loaded")

    # --- 4. Python flag detection ---
    config = {
        "spike_threshold": args.spike,
        "duration_spike": args.dur_spike,
        "off_hours_severity": "medium",
    }
    flags = detect_flags(session, profile, config)

    # Chunk karsilastirma flag'leri ekle
    chunk_flags = compare_with_chunks(session, chunks)
    flags.extend(chunk_flags)

    print(f"\n  [Flags] Python detected {len(flags)} flag(s)")

    # --- 5. LLM yorumlama (flag varsa ve model belirtilmisse) ---
    llm_result = None
    if flags and args.model:
        print(f"  [LLM] Sending to {args.model} for interpretation...")
        client = OpenAI(base_url=args.endpoint, api_key="not-needed")
        t = time.time()
        llm_result = interpret_with_llm(session, profile, flags, client, args.model)
        print(f"  [OK] LLM response in {time.time()-t:.1f}s")
    elif not flags:
        print(f"  [OK] No flags - session is NORMAL (LLM not needed)")
        llm_result = {"riskScore": 0, "verdict": "normal", "anomalies": [], "reasoning": "No anomalies detected."}

    # --- 6. Rapor olustur ---
    report = build_report(session, flags, llm_result)
    print_report(report)

    # --- 7. Kaydet (opsiyonel) ---
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"\n  ğŸ’¾ Report saved: {args.output}")


if __name__ == "__main__":
    main()

