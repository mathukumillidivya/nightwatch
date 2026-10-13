# Reproduce these results

## Check the published numbers (no API key, a few seconds)

```bash
pip install -r requirements.txt
python reproduce.py
```

`reproduce.py` re-scores every saved run with the same scoring code and compares each number with the
committed results. It prints `MATCH` or `DIFFERENT` per file.

## What each part is

| | Where |
|---|---|
| System frozen before the held-out test | commit `ca87443` |
| Dataset | OTRF Security-Datasets (MIT), Windows host recordings: `data/cases.jsonl`, labels in `data/labels.json`, split in `data/split.json`. `scripts/build_cases.py` rebuilds them from the OTRF repository. See [DATA.md](DATA.md). |
| ATT&CK knowledge base | `data/attack.json`, built from MITRE's STIX bundle v19.2 by `scripts/build_attack.py` |
| Raw model outputs | `results/runs/<run>/` (one JSON line per alert, with the full trace, tokens and cost) |
| Scoring code | `scripts/evaluate.py` (held-out comparison, paired bootstrap), `scripts/score_redteam.py` and `scripts/summarize_redteam.py` (prompt injection) |
| Published results | `results/test-comparison.json`, `results/redteam.json`, spending in `results/spend.json` |

## Re-run the agents from scratch

Needs an Anthropic API key. The held-out test cost about $2.70 for both systems.

```bash
git checkout ca87443
export ANTHROPIC_API_KEY=...      # never commit this
python scripts/run.py --system nightwatch  --split test --run-id my-nightwatch --budget 2.5
python scripts/run.py --system single_call --split test --run-id my-single     --budget 1.0
python scripts/evaluate.py results/runs/my-single results/runs/my-nightwatch
```

Model outputs vary slightly between runs at temperature 0, so a fresh run lands close to, not exactly on,
the published figures. The GitHub workflow `run.yml` does the same in Actions.

## Checks added after the test

These came after the frozen evaluation and do not change its numbers. In GitHub: Actions > extra-evals. It downloads
the benign recordings (NextronSystems/evtx-baseline, Apache-2.0), builds `data/benign.jsonl`, runs both systems on it
and on `data/redteam_wide.jsonl`, and runs the quote-support check. To re-score the saved runs without a key:

```bash
python scripts/score_benign.py --run nightwatch=results/runs/benign-nightwatch single_call=results/runs/benign-single \
  --clean nightwatch=results/runs/test-nightwatch single_call=results/runs/test-single
python scripts/score_redteam.py --clean results/runs/test-nightwatch --attacked results/runs/rt-wide-nightwatch-guarded \
  --planted data/redteam_wide.jsonl
```

`results/quote_support.json` holds the quote-support results (`scripts/quote_support.py`, needs a key to re-run).
