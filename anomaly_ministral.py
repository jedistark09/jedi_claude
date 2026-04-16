import argparse
import json
import math
import os
import re
import time
from pathlib import Path

from openai import OpenAI


SYSTEM_PROMPT = """You are a PAM / UBA security risk analyst.

You will be given:
1. The user's historical behavior profile
2. A summary of the latest chunk(s)
3. A summary of the new session
4. A list of anomaly flags produced by Python

Your task:
- Evaluate the Python flags in context
- Produce the final risk score
- Produce the final verdict

Important:
- Python flags are only pre-filters; they are not risk scores
- Not all flags have equal importance
- Evaluate commands, applications, URLs, time, duration, IPs, and chunk context together
- Do not overreact to weak standalone signals
- Do not downplay strong signals
- Increase risk when multiple signals appear together

Flag evaluation logic:

Low impact:
- new_urls
- off_hours
- duration_spike

Medium impact:
- new_applications
- command_count_spike
- new_vs_latest_chunk
- escalation_vs_chunk

High impact:
- new_commands
- new_target_ips
- dormant_reactivation

Combinations that increase risk:
- new_commands + off_hours
- new_commands + new_target_ips
- new_commands + new_applications
- new_commands + dormant_reactivation
- new_target_ips + command_count_spike
- off_hours + command_count_spike + duration_spike
- new_vs_latest_chunk + escalation_vs_chunk
- 3 or more different flags appearing together

Command evaluation rules:
- Commands suggesting privilege activity, credential access, user creation, reconnaissance, scanning, persistence, defense evasion, remote access, or admin tooling should significantly increase risk
- Give higher weight to commands related to network discovery, user management, privilege checks, credential access, or exploit-like behavior

Application evaluation rules:
- Packet capture, remote admin, exploitation, shell, credential, network analysis, or previously unseen admin tools should increase risk

URL evaluation rules:
- A new URL alone is usually a low-impact signal
- But increase its impact if it suggests exploit activity, phishing, malware, credential access, reconnaissance, cracking, or attack research

Time evaluation rules:
- Off-hours usage alone is not critical
- But it should raise risk when combined with stronger flags

Score ranges:
- 0-19: normal
- 20-39: low suspicion
- 40-59: medium risk
- 60-79: high risk
- 80-100: critical

Verdict rules:
- normal: weak or benign signals
- suspicious: meaningful risk exists and review is needed
- critical: strong evidence of misuse or attack behavior

Response format:
Return only valid JSON. Do not use Markdown.
Write all natural-language output in Turkish. Keep JSON keys unchanged.

JSON schema:
{
  "riskScore": 0-100,
  "verdict": "normal|suspicious|critical",
  "anomalies": [
    {
      "type": "flag_type",
      "detail": "Why this flag is important or weak in context",
      "severity": "low|medium|high|critical"
    }
  ],
  "reasoning": "A single-paragraph overall risk assessment"
}

Rules:
- riskScore and verdict must be consistent
- do not treat all flags as equally weighted
- rely only on the provided data
- avoid unnecessary dramatization
- be cautious when evidence is weak
- raise risk when evidence combines into a stronger pattern
- write all "detail" and "reasoning" text in Turkish
"""


def create_client(api_base: str) -> OpenAI:
    return OpenAI(base_url=api_base, api_key="not-needed")


def parse_duration(value: str) -> int:
    try:
        parts = value.split(":")
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        if len(parts) == 2:
            return int(parts[0]) * 60 + int(parts[1])
    except Exception:
        pass
    return 0


def extract_ips(commands: list[str]) -> list[str]:
    pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    ips = set()
    for command in commands:
        ips.update(pattern.findall(command))
    return sorted(ips)


def parse_analyzed_session(path: Path) -> dict | None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        return None

    session = {
        "sessionId": path.stem.replace("analyzed_", ""),
        "timestamp": "",
        "duration": 0,
        "urls": [],
        "commands": [],
        "apps": [],
        "summary": "",
    }

    for block in data:
        category = block.get("category", "")
        items = block.get("items", {})
        if category == "URLs":
            session["urls"] = list(items.keys())
        elif category == "Commands":
            session["commands"] = [cmd for cmd, count in items.items() if count > 0]
        elif category == "Applications":
            session["apps"] = [app for app, count in items.items() if count > 0]
        elif category == "Summary":
            session["summary"] = items.get("text", "")
        elif category == "Session Start":
            session["timestamp"] = items.get("text", "")
        elif category == "Session Duration":
            session["duration"] = parse_duration(items.get("text", "0:00:00"))

    return session if session["timestamp"] else None


def build_chunk_profile(sessions: list[dict], chunk_index: int) -> dict:
    url_freq = {}
    cmd_freq = {}
    app_freq = {}
    hours = []
    durations = []
    commands_per_session = []
    known_ips = set()

    for session in sessions:
        for url in session["urls"]:
            url_freq[url] = url_freq.get(url, 0) + 1
        for command in session["commands"]:
            cmd_freq[command] = cmd_freq.get(command, 0) + 1
        for app in session["apps"]:
            app_freq[app] = app_freq.get(app, 0) + 1

        try:
            hours.append(int(session["timestamp"][11:13]))
        except Exception:
            pass

        durations.append(session["duration"])
        commands_per_session.append(len(session["commands"]))
        known_ips.update(extract_ips(session["commands"]))

    buf = 1
    return {
        "chunkIndex": chunk_index,
        "firstSeen": sessions[0]["timestamp"],
        "lastSeen": sessions[-1]["timestamp"],
        "totalSessions": len(sessions),
        "urlFrequency": dict(sorted(url_freq.items(), key=lambda x: -x[1])),
        "commandFrequency": dict(sorted(cmd_freq.items(), key=lambda x: -x[1])),
        "appFrequency": dict(sorted(app_freq.items(), key=lambda x: -x[1])),
        "activeHours": {
            "rangeStart": max(0, min(hours) - buf) if hours else 0,
            "rangeEnd": min(23, max(hours) + buf) if hours else 23,
            "buffer": buf,
            "sessionHours": hours,
        },
        "avgSessionDuration": round(sum(durations) / len(sessions)) if sessions else 0,
        "avgCommandsPerSession": round(sum(commands_per_session) / len(sessions), 1) if sessions else 0,
        "sessionDurations": durations,
        "commandsPerSession": commands_per_session,
        "knownTargetIPs": sorted(known_ips),
        "sessions": [
            {
                "sessionId": session["sessionId"],
                "timestamp": session["timestamp"],
                "duration": session["duration"],
                "urls": session["urls"],
                "commands": session["commands"],
                "apps": session["apps"],
            }
            for session in sessions
        ],
    }


def build_profile(analyzed_dir: Path, chunk_size: int) -> tuple[dict, list[dict]]:
    sessions = []
    for path in sorted(analyzed_dir.glob("analyzed_*.json")):
        session = parse_analyzed_session(path)
        if session:
            sessions.append(session)

    if not sessions:
        raise SystemExit(f"No valid analyzed sessions found in {analyzed_dir}")

    sessions.sort(key=lambda item: item["timestamp"])
    chunks = []
    for index in range(math.ceil(len(sessions) / chunk_size)):
        start = index * chunk_size
        group = sessions[start:start + chunk_size]
        chunks.append(build_chunk_profile(group, index + 1))

    url_freq = {}
    cmd_freq = {}
    app_freq = {}
    all_hours = []
    all_durations = []
    all_commands_per = []
    all_ips = set()
    all_sessions = []

    for chunk in chunks:
        for key, value in chunk["urlFrequency"].items():
            url_freq[key] = url_freq.get(key, 0) + value
        for key, value in chunk["commandFrequency"].items():
            cmd_freq[key] = cmd_freq.get(key, 0) + value
        for key, value in chunk["appFrequency"].items():
            app_freq[key] = app_freq.get(key, 0) + value
        all_hours.extend(chunk["activeHours"]["sessionHours"])
        all_durations.extend(chunk["sessionDurations"])
        all_commands_per.extend(chunk["commandsPerSession"])
        all_ips.update(chunk["knownTargetIPs"])
        all_sessions.extend(chunk["sessions"])

    buf = chunks[0]["activeHours"]["buffer"]
    profile = {
        "firstSeen": chunks[0]["firstSeen"],
        "lastSeen": chunks[-1]["lastSeen"],
        "totalSessions": len(sessions),
        "totalChunks": len(chunks),
        "urlFrequency": dict(sorted(url_freq.items(), key=lambda x: -x[1])),
        "commandFrequency": dict(sorted(cmd_freq.items(), key=lambda x: -x[1])),
        "appFrequency": dict(sorted(app_freq.items(), key=lambda x: -x[1])),
        "activeHours": {
            "rangeStart": max(0, min(all_hours) - buf) if all_hours else 0,
            "rangeEnd": min(23, max(all_hours) + buf) if all_hours else 23,
            "buffer": buf,
            "sessionHours": all_hours,
        },
        "avgSessionDuration": round(sum(all_durations) / len(sessions)) if sessions else 0,
        "avgCommandsPerSession": round(sum(all_commands_per) / len(sessions), 1) if sessions else 0,
        "sessionDurations": all_durations[-20:],
        "commandsPerSession": all_commands_per[-20:],
        "knownTargetIPs": sorted(all_ips),
        "recentSessions": all_sessions[-10:],
    }
    return profile, chunks


def build_llm_input(report: dict, profile: dict, chunks: list[dict]) -> dict:
    latest_chunk = chunks[-1] if chunks else {}
    return {
        "profile": {
            "totalSessions": profile.get("totalSessions", 0),
            "period": {
                "firstSeen": profile.get("firstSeen", ""),
                "lastSeen": profile.get("lastSeen", ""),
            },
            "activeHours": profile.get("activeHours", {}),
            "avgSessionDuration": profile.get("avgSessionDuration", 0),
            "avgCommandsPerSession": profile.get("avgCommandsPerSession", 0),
            "topCommands": list(profile.get("commandFrequency", {}).keys())[:15],
            "topApps": list(profile.get("appFrequency", {}).keys())[:10],
            "topUrls": list(profile.get("urlFrequency", {}).keys())[:10],
            "knownTargetIPs": profile.get("knownTargetIPs", []),
        },
        "latestChunk": {
            "chunkIndex": latest_chunk.get("chunkIndex"),
            "firstSeen": latest_chunk.get("firstSeen"),
            "lastSeen": latest_chunk.get("lastSeen"),
            "avgCommandsPerSession": latest_chunk.get("avgCommandsPerSession", 0),
            "topCommands": list(latest_chunk.get("commandFrequency", {}).keys())[:10],
            "topApps": list(latest_chunk.get("appFrequency", {}).keys())[:8],
            "topUrls": list(latest_chunk.get("urlFrequency", {}).keys())[:8],
        },
        "newSession": {
            "sessionId": report.get("sessionId", ""),
            "timestamp": report.get("timestamp", ""),
            "duration": f"{report.get('duration', 0)}s",
            "urls": report.get("session", {}).get("urls", []),
            "commands": report.get("session", {}).get("commands", []),
            "apps": report.get("session", {}).get("apps", []),
        },
        "pythonFlags": report.get("pythonFlags", []),
    }


def interpret_with_ministral(
    client: OpenAI,
    model: str,
    llm_input: dict,
    max_retries: int = 3,
) -> dict:
    user_content = json.dumps(llm_input, ensure_ascii=False, indent=2)

    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content + "\n/no_think"},
                ],
                temperature=0,
                max_tokens=2000,
                seed=42,
            )

            raw = response.choices[0].message.content.strip()
            raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
            raw = raw.replace("```json", "").replace("```", "").strip()

            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                raw = raw[start:end]

            return json.loads(raw)
        except json.JSONDecodeError as exc:
            print(f"  [WARN] JSON parse error ({attempt + 1}/{max_retries}): {exc}")
            time.sleep(1)
        except Exception as exc:
            print(f"  [WARN] LLM error ({attempt + 1}/{max_retries}): {exc}")
            time.sleep(2)

    return {
        "riskScore": -1,
        "verdict": "error",
        "anomalies": [],
        "reasoning": "Ministral risk analysis failed.",
    }


def build_result(report: dict, llm_result: dict) -> dict:
    result = dict(report)
    result["llmAssessment"] = llm_result
    result["finalVerdict"] = llm_result.get("verdict", "error")
    result["finalRiskScore"] = llm_result.get("riskScore")
    return result


def process_report(report_path: Path, out_path: Path, client: OpenAI, model: str, profile: dict, chunks: list[dict]) -> None:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    print(f"[Report] {report_path.name}")
    llm_input = build_llm_input(report, profile, chunks)
    start = time.time()
    llm_result = interpret_with_ministral(client, model, llm_input)
    elapsed = time.time() - start
    result = build_result(report, llm_result)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  [Saved] {out_path.name} ({elapsed:.1f}s) -> verdict={result['finalVerdict']} risk={result['finalRiskScore']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ministral risk analyst for anomaly reports."
    )
    parser.add_argument("--uba-dir", default="./analyzed_ministral", help="UBA veri setini olusturan analyzed session klasoru")
    parser.add_argument("--reports-dir", default="./anomaly_detector", help="Python flag raporlarinin bulundugu klasor")
    parser.add_argument("--output-dir", default="./anomaly_ministral_results", help="Ministral degerlendirme cikti klasoru")
    parser.add_argument("--endpoint", default="http://localhost:11434/v1", help="OpenAI-compatible endpoint")
    parser.add_argument("--model", default="ministral-3:14b", help="Risk analisti modeli")
    parser.add_argument("--chunk-size", type=int, default=3, help="UBA profile olustururken kullanilacak chunk boyutu")
    args = parser.parse_args()

    uba_dir = Path(args.uba_dir)
    reports_dir = Path(args.reports_dir)
    output_dir = Path(args.output_dir)

    if not uba_dir.is_dir():
        raise SystemExit(f"UBA dataset klasoru bulunamadi: {uba_dir}")
    if not reports_dir.is_dir():
        raise SystemExit(f"Reports klasoru bulunamadi: {reports_dir}")

    report_files = sorted(reports_dir.glob("report_*.json"))
    if not report_files:
        raise SystemExit(f"Rapor JSON dosyasi bulunamadi: {reports_dir}")

    profile, chunks = build_profile(uba_dir, args.chunk_size)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Profile] sessions={profile['totalSessions']} chunks={profile['totalChunks']}")
    print(f"[Reports] {len(report_files)} file(s)")
    print(f"[Model] {args.model}")

    client = create_client(args.endpoint)
    for report_path in report_files:
        out_path = output_dir / f"ministral_{report_path.name}"
        process_report(report_path, out_path, client, args.model, profile, chunks)

    print(f"[Done] Results saved in {output_dir}")


if __name__ == "__main__":
    main()
