#!/usr/bin/env python3
"""GoTestWAF report -> summary, thresholds and regression seed candidates.

  gotestwaf_report.py <report.json> [--min-tp PCT] [--min-tn PCT]
                      [--csv report.csv --candidates out.jsonl]

Exits 1 when the true-positive or true-negative score is under its
threshold. Each bypass sent where corpus/regression can carry it (query,
form, URL path) becomes a candidate seed: decoded as GoTestWAF encoded it,
to be triaged (a real bypass, fixed, then added to corpus/regression).
The bypasses are read from the CSV report: the JSON one repeats the
encoder in its placeholder field (GoTestWAF 0.5).
"""
import argparse
import base64
import csv
import json
import sys
import urllib.parse

# GoTestWAF placeholder -> corpus/regression carrier
CARRIERS = {"URLParam": "query", "HTMLForm": "form", "URLPath": "path"}


def decode(payload, encoder):
    """(text, seed encoding) of a payload as GoTestWAF sent it, or None."""
    if encoder == "Base64Flat":
        try:
            raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            return raw.decode("utf-8"), "base64url"
        except (ValueError, UnicodeDecodeError):
            return None
    if encoder == "URL":
        return urllib.parse.unquote(payload), ""
    if encoder == "Plain":
        return payload, ""
    return None


def summarize(report):
    s = report["summary"]
    tp = s["true_positive_tests"]
    tn = s["true_negative_tests"]
    return {
        "score": report.get("score"),
        "tp": tp["score"],
        "tp_blocked": tp["summary"]["blocked_tests"],
        "tp_resolved": tp["summary"]["resolved_tests"],
        "tn": tn["score"],
        "tn_blocked": tn["summary"]["blocked_tests"],
        "tn_resolved": tn["summary"]["resolved_tests"],
    }


def bypasses(csv_path):
    """True-positive payloads that passed, from a GoTestWAF CSV report."""
    csv.field_size_limit(sys.maxsize)
    with open(csv_path, newline="") as f:
        for r in csv.DictReader(f):
            if r.get("Test Result") == "failed" and r.get("Set") != "false-pos":
                yield {"payload": r["Payload"], "placeholder": r["Placeholder"],
                       "encoder": r["Encoder"], "test_set": r["Set"], "test_case": r["Case"]}


def candidates(rows):
    out, seen = [], set()
    for b in rows:
        carrier = CARRIERS.get(b.get("placeholder", ""))
        dec = decode(b.get("payload", ""), b.get("encoder", ""))
        if carrier is None or dec is None:
            continue
        text, encoding = dec
        key = (text, carrier, encoding)
        if not text or key in seen:
            continue
        seen.add(key)
        out.append({
            "id": f"gtw-candidate-{len(out) + 1:03d}",
            "payload": text,
            "attack_type": b.get("test_case", ""),
            "carrier": carrier,
            "encoding": encoding,
            "source": f"GoTestWAF {b.get('test_set')}/{b.get('test_case')} "
                      f"{b.get('placeholder')} {b.get('encoder')}",
        })
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--min-tp", type=float, default=0)
    ap.add_argument("--min-tn", type=float, default=0)
    ap.add_argument("--csv")
    ap.add_argument("--candidates")
    a = ap.parse_args(argv)
    with open(a.report) as f:
        report = json.load(f)
    s = summarize(report)
    print(f"GoTestWAF: true positive {s['tp']:.2f}% ({s['tp_blocked']}/{s['tp_resolved']}), "
          f"true negative {s['tn']:.2f}% ({s['tn_resolved'] - s['tn_blocked']}/{s['tn_resolved']} passed), "
          f"score {s['score']}")
    if a.candidates and a.csv:
        c = candidates(bypasses(a.csv))
        with open(a.candidates, "w") as f:
            for row in c:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"{len(c)} regression seed candidates in {a.candidates}")
    bad = []
    if s["tp"] < a.min_tp:
        bad.append(f"true positive {s['tp']:.2f}% < {a.min_tp}%")
    if s["tn"] < a.min_tn:
        bad.append(f"true negative {s['tn']:.2f}% < {a.min_tn}%")
    for b in bad:
        print("FAIL:", b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
