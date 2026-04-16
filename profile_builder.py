"""
Profile Builder v2 — PAM UBA Pipeline
=======================================
Session'lari kronolojik sirada N'erli gruplara boler.
Her grup icin bir ozet profil olusturur, sonra hepsini birlestirir.

9 session, --chunk 3 ile:
  Grup 1 (session 1-3) → chunk_1.json
  Grup 2 (session 4-6) → chunk_2.json
  Grup 3 (session 7-9) → chunk_3.json
  Birlesik             → profile.json

Kullanim:
  python profile_builder.py -i ./analyzed -o ./profiles -u superadmin -t administrator@10.0.1.50 --chunk 3
"""

import json, os, sys, re, argparse, math
from pathlib import Path
from datetime import datetime


# ============================================================
# ANALYZED SESSION PARSER
# ============================================================

def parse_analyzed_session(filepath: str) -> dict | None:
    """Bir analyzed JSON dosyasini oku, normalize edilmis session dict dondur."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        return None

    session = {
        "sessionId": Path(filepath).stem.replace("analyzed_", ""),
        "timestamp": "",
        "duration": 0,
        "urls": [],
        "commands": [],
        "apps": [],
        "summary": "",
    }

    for block in data:
        cat = block.get("category", "")
        items = block.get("items", {})

        if cat == "URLs":
            session["urls"] = list(items.keys())
        elif cat == "Commands":
            session["commands"] = [cmd for cmd, count in items.items() if count > 0]
        elif cat == "Applications":
            session["apps"] = [app for app, count in items.items() if count > 0]
        elif cat == "Summary":
            session["summary"] = items.get("text", "")
        elif cat == "Session Start":
            session["timestamp"] = items.get("text", "")
        elif cat == "Session Duration":
            session["duration"] = _parse_duration(items.get("text", "0:00:00"))

    return session if session["timestamp"] else None


def _parse_duration(dur_str: str) -> int:
    try:
        parts = dur_str.split(":")
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        elif len(parts) == 2:
            return int(parts[0]) * 60 + int(parts[1])
        return 0
    except (ValueError, IndexError):
        return 0


def _extract_ips(commands: list[str]) -> list[str]:
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    ips = set()
    for cmd in commands:
        for match in ip_pattern.findall(cmd):
            ips.add(match)
    return sorted(ips)


# ============================================================
# CHUNK PROFILE (tek bir grup icin ozet)
# ============================================================

def build_chunk_profile(
    sessions: list[dict],
    chunk_index: int,
    user_id: str = "",
    account_target: str = "",
) -> dict:
    """N session'dan bir chunk ozet profili olustur."""

    url_freq = {}
    cmd_freq = {}
    app_freq = {}
    hours = []
    durations = []
    cmds_per = []
    all_ips = set()

    for s in sessions:
        # Frequency: kac session'da goruldu (1 per session)
        for url in s["urls"]:
            url_freq[url] = url_freq.get(url, 0) + 1
        for cmd in s["commands"]:
            cmd_freq[cmd] = cmd_freq.get(cmd, 0) + 1
        for app in s["apps"]:
            app_freq[app] = app_freq.get(app, 0) + 1

        # Saat
        try:
            hours.append(int(s["timestamp"][11:13]))
        except (ValueError, IndexError):
            pass

        # Metrikler
        durations.append(s["duration"])
        cmds_per.append(len(s["commands"]))

        # IP'ler
        for ip in _extract_ips(s["commands"]):
            all_ips.add(ip)

    # Aktif saat araligi
    buf = 1
    range_start = max(0, min(hours) - buf) if hours else 0
    range_end = min(23, max(hours) + buf) if hours else 23

    total = len(sessions)
    avg_dur = round(sum(durations) / total) if total else 0
    avg_cmds = round(sum(cmds_per) / total, 1) if total else 0

    # Sort frequencies
    url_freq = dict(sorted(url_freq.items(), key=lambda x: -x[1]))
    cmd_freq = dict(sorted(cmd_freq.items(), key=lambda x: -x[1]))
    app_freq = dict(sorted(app_freq.items(), key=lambda x: -x[1]))

    return {
        "chunkIndex": chunk_index,
        "userId": user_id,
        "accountTarget": account_target,
        "firstSeen": sessions[0]["timestamp"],
        "lastSeen": sessions[-1]["timestamp"],
        "totalSessions": total,

        "urlFrequency": url_freq,
        "commandFrequency": cmd_freq,
        "appFrequency": app_freq,

        "activeHours": {
            "rangeStart": range_start,
            "rangeEnd": range_end,
            "buffer": buf,
            "sessionHours": hours,
        },

        "avgSessionDuration": avg_dur,
        "avgCommandsPerSession": avg_cmds,
        "sessionDurations": durations,
        "commandsPerSession": cmds_per,
        "knownTargetIPs": sorted(all_ips),

        "sessions": [
            {
                "sessionId": s["sessionId"],
                "timestamp": s["timestamp"],
                "duration": s["duration"],
                "urls": s["urls"],
                "commands": s["commands"],
                "apps": s["apps"],
                "verdict": "normal",
            }
            for s in sessions
        ],
    }


# ============================================================
# MERGE CHUNKS → FINAL PROFILE
# ============================================================

def merge_chunks(chunks: list[dict], user_id: str = "", account_target: str = "") -> dict:
    """Chunk ozetlerini birlestirir, tek bir genel profil olusturur."""

    url_freq = {}
    cmd_freq = {}
    app_freq = {}
    all_hours = []
    all_durations = []
    all_cmds_per = []
    all_ips = set()
    all_sessions = []

    for chunk in chunks:
        # Frequency birlestirme
        for k, v in chunk["urlFrequency"].items():
            url_freq[k] = url_freq.get(k, 0) + v
        for k, v in chunk["commandFrequency"].items():
            cmd_freq[k] = cmd_freq.get(k, 0) + v
        for k, v in chunk["appFrequency"].items():
            app_freq[k] = app_freq.get(k, 0) + v

        all_hours.extend(chunk["activeHours"]["sessionHours"])
        all_durations.extend(chunk["sessionDurations"])
        all_cmds_per.extend(chunk["commandsPerSession"])
        for ip in chunk["knownTargetIPs"]:
            all_ips.add(ip)
        all_sessions.extend(chunk["sessions"])

    buf = chunks[0]["activeHours"]["buffer"] if chunks else 1
    range_start = max(0, min(all_hours) - buf) if all_hours else 0
    range_end = min(23, max(all_hours) + buf) if all_hours else 23

    total = sum(c["totalSessions"] for c in chunks)
    avg_dur = round(sum(all_durations) / total) if total else 0
    avg_cmds = round(sum(all_cmds_per) / total, 1) if total else 0

    # Son 10 session
    recent = all_sessions[-10:] if len(all_sessions) > 10 else all_sessions

    return {
        "userId": user_id or (chunks[0]["userId"] if chunks else ""),
        "accountTarget": account_target or (chunks[0]["accountTarget"] if chunks else ""),
        "firstSeen": chunks[0]["firstSeen"] if chunks else "",
        "lastSeen": chunks[-1]["lastSeen"] if chunks else "",
        "profileUpdatedAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totalSessions": total,
        "totalChunks": len(chunks),

        "urlFrequency": dict(sorted(url_freq.items(), key=lambda x: -x[1])),
        "commandFrequency": dict(sorted(cmd_freq.items(), key=lambda x: -x[1])),
        "appFrequency": dict(sorted(app_freq.items(), key=lambda x: -x[1])),

        "activeHours": {
            "rangeStart": range_start,
            "rangeEnd": range_end,
            "buffer": buf,
            "sessionHours": all_hours,
        },

        "avgSessionDuration": avg_dur,
        "avgCommandsPerSession": avg_cmds,
        "sessionDurations": all_durations[-20:],
        "commandsPerSession": all_cmds_per[-20:],
        "knownTargetIPs": sorted(all_ips),
        "recentSessions": recent,
    }


# ============================================================
# DISPLAY
# ============================================================

def print_chunk_summary(chunk: dict):
    n = chunk["totalSessions"]
    print(f"  Chunk {chunk['chunkIndex']}: {n} sessions "
          f"({chunk['firstSeen'][:16]} → {chunk['lastSeen'][:16]})")
    print(f"    URLs:  {', '.join(list(chunk['urlFrequency'].keys())[:4]) or '(none)'}")
    print(f"    Cmds:  {', '.join(list(chunk['commandFrequency'].keys())[:4]) or '(none)'}")
    print(f"    Apps:  {', '.join(list(chunk['appFrequency'].keys())[:4]) or '(none)'}")
    print(f"    Avg:   {chunk['avgSessionDuration']}s, {chunk['avgCommandsPerSession']} cmds/session")
    if chunk["knownTargetIPs"]:
        print(f"    IPs:   {', '.join(chunk['knownTargetIPs'])}")
    print()


def print_profile_summary(profile: dict):
    t = profile["totalSessions"]
    print(f"\n{'='*60}")
    print(f"  MERGED PROFILE — {t} sessions in {profile.get('totalChunks', '?')} chunks")
    print(f"{'='*60}")
    print(f"  User:     {profile['userId'] or '(not set)'}")
    print(f"  Target:   {profile['accountTarget'] or '(not set)'}")
    print(f"  Period:   {profile['firstSeen'][:16]} → {profile['lastSeen'][:16]}")

    ah = profile["activeHours"]
    print(f"  Hours:    {ah['rangeStart']:02d}:00 — {ah['rangeEnd']:02d}:59 (±{ah['buffer']}h)")
    print(f"  Avg dur:  {profile['avgSessionDuration']}s ({profile['avgSessionDuration']/60:.1f} min)")
    print(f"  Avg cmds: {profile['avgCommandsPerSession']}")

    print(f"\n  URLs ({len(profile['urlFrequency'])}):")
    for k, v in list(profile["urlFrequency"].items())[:5]:
        print(f"    {k:30s} {v}/{t} sessions ({v/t*100:.0f}%)")

    print(f"\n  Commands ({len(profile['commandFrequency'])}):")
    for k, v in list(profile["commandFrequency"].items())[:5]:
        print(f"    {k:30s} {v}/{t} sessions ({v/t*100:.0f}%)")

    print(f"\n  Apps ({len(profile['appFrequency'])}):")
    for k, v in list(profile["appFrequency"].items())[:5]:
        print(f"    {k:30s} {v}/{t} sessions ({v/t*100:.0f}%)")

    if profile["knownTargetIPs"]:
        print(f"\n  Known IPs: {', '.join(profile['knownTargetIPs'])}")
    print(f"{'='*60}")


# ============================================================
# MAIN
# ============================================================

def main():
    p = argparse.ArgumentParser(
        description="PAM Profile Builder v2 — Chunked",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python profile_builder.py -i ./analyzed -o ./profiles -u superadmin --chunk 3
  python profile_builder.py -i ./analyzed -o ./profiles --chunk 5
        """,
    )
    p.add_argument("--input", "-i", required=True, help="Analyzed JSON klasoru")
    p.add_argument("--output", "-o", required=True, help="Cikti klasoru")
    p.add_argument("--user", "-u", default="", help="Kullanici ID")
    p.add_argument("--target", "-t", default="", help="Hedef hesap (user@host)")
    p.add_argument("--chunk", "-c", type=int, default=3, help="Grup boyutu (default: 3)")
    p.add_argument("--buffer", "-b", type=int, default=1, help="Aktif saat tampon (default: 1h)")
    args = p.parse_args()

    # --- 1. Tum analyzed dosyalari oku ve sirala ---
    files = sorted(Path(args.input).glob("analyzed_*.json"))
    if not files:
        print(f"No analyzed files in {args.input}")
        sys.exit(1)

    sessions = []
    for f in files:
        s = parse_analyzed_session(str(f))
        if s:
            sessions.append(s)

    sessions.sort(key=lambda x: x["timestamp"])
    print(f"  {len(sessions)} sessions found, chunk size: {args.chunk}\n")

    # --- 2. Kronolojik sirada chunk'lara bol ---
    chunk_size = args.chunk
    num_chunks = math.ceil(len(sessions) / chunk_size)

    os.makedirs(args.output, exist_ok=True)
    chunks = []

    for i in range(num_chunks):
        start = i * chunk_size
        end = min(start + chunk_size, len(sessions))
        group = sessions[start:end]

        chunk = build_chunk_profile(
            group,
            chunk_index=i + 1,
            user_id=args.user,
            account_target=args.target,
        )
        chunk["activeHours"]["buffer"] = args.buffer
        chunks.append(chunk)

        # Chunk dosyasini kaydet
        chunk_path = os.path.join(args.output, f"chunk_{i+1}.json")
        with open(chunk_path, "w", encoding="utf-8") as f:
            json.dump(chunk, f, ensure_ascii=False, indent=2)

        print_chunk_summary(chunk)

    # --- 3. Chunk'lari birlestir ---
    profile = merge_chunks(chunks, args.user, args.target)

    profile_path = os.path.join(args.output, "profile.json")
    with open(profile_path, "w", encoding="utf-8") as f:
        json.dump(profile, f, ensure_ascii=False, indent=2)

    print_profile_summary(profile)
    print(f"\n  Chunks: {num_chunks} files in {args.output}/")
    print(f"  Profile: {profile_path}")


if __name__ == "__main__":
    main()
