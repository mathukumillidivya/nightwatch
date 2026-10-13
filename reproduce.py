"""Re-score Nightwatch's published runs and check every number against the committed results.

No API key and no download needed; it takes a few seconds. The raw model outputs are in results/runs/,
the scoring code is scripts/evaluate.py and scripts/summarize_redteam.py, the system was frozen at
commit ca87443 before the held-out test was run. To re-run the agents themselves, see REPRODUCE.md.

Usage: python reproduce.py
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp(prefix="reproduce-"))


def run(*args, cwd=None):
    """Run one of the repository's own scripts with this Python, quietly."""
    subprocess.run([sys.executable, *map(str, args)], cwd=cwd or ROOT, check=True, stdout=subprocess.DEVNULL)


def differences(a, b, path=""):
    """Every place two JSON values differ, allowing for rounding in the last decimal places."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = [f"{path}/{k}: only in one file" for k in set(a) ^ set(b)]
        return out + [d for k in set(a) & set(b) for d in differences(a[k], b[k], f"{path}/{k}")]
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [f"{path}: {len(a)} items against {len(b)}"]
        return [d for i, (x, y) in enumerate(zip(a, b)) for d in differences(x, y, f"{path}[{i}]")]
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool):
        return [] if abs(a - b) <= 1e-3 else [f"{path}: {a} against {b}"]
    return [] if a == b else [f"{path}: {str(a)[:40]} against {str(b)[:40]}"]


def check(name, recomputed, published):
    diff = differences(recomputed, published)
    print(f"  {'MATCH    ' if not diff else 'DIFFERENT'} {name}")
    for d in diff[:5]:
        print(f"             {d}")
    return not diff


def rerun_in_place(name, files, *args, cwd=None):
    """For scripts that write next to the published files: run, compare with what was there, then put it back."""
    before = {f: (ROOT / f).read_text() for f in files}
    try:
        run(*args, cwd=cwd)
        return all([check(f"{name}: {f}", json.loads((ROOT / f).read_text()), json.loads(before[f])) for f in files])
    finally:
        for f, text in before.items():
            (ROOT / f).write_text(text)


def main():
    print("Nightwatch: re-scoring the published runs with the repository's own scoring code.\n")
    run("scripts/evaluate.py", "results/runs/test-single", "results/runs/test-nightwatch", "--out", TMP / "test.json")
    r = json.loads((TMP / "test.json").read_text())
    ok = check("64 held-out alerts (results/test-comparison.json)", r, json.loads((ROOT / "results/test-comparison.json").read_text()))
    ok &= rerun_in_place("prompt-injection runs", ["results/redteam.json"], "scripts/summarize_redteam.py")
    nw, sc = r["test-nightwatch"], r["test-single"]
    print(f"\n  First technique = label   Nightwatch {nw['top1']:.1%}   single AI call {sc['top1']:.1%}")
    print(f"  Findings with a verified quote   Nightwatch {nw['grounded']:.1%}   single AI call {sc['grounded']:.1%}")
    print("\nEvery number matches the published results." if ok else "\nSome numbers differ; see above.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
