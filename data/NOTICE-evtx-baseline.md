# Benign recordings

`data/benign.jsonl` (built by `scripts/build_benign.py` in the `extra-evals` workflow) contains windows of
ordinary Windows activity taken from [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline),
licensed under the Apache License 2.0. The events are reduced to Nightwatch's triage view (templates, rarity,
the 50 most unusual events); nothing else was changed. The mixed alerts (`MX-*`) add events from the OTRF
Security Datasets recordings (see `LICENSE-OTRF`).
