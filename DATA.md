# Data sources

## OTRF Security-Datasets (MIT licence)

`data/cases.jsonl` is derived from the Windows host recordings of the Open Threat Research Forge
[Security-Datasets](https://github.com/OTRF/Security-Datasets) project (`datasets/atomic/windows/*/host`),
Copyright (c) 2021 Open Threat Research Forge, released under the MIT licence (full text in `data/LICENSE-OTRF`). Each recording was captured in a
lab domain while one adversary technique was executed; the technique labels in `data/labels.json` come from the
project's `_metadata/*.yaml` files. `scripts/build_cases.py` reduces each recording to the triage view and index
used here. One dataset labelled `T0000` (no technique) is excluded, leaving 105 recordings from 94 datasets.

## MITRE ATT&CK (v19.2)

`data/attack.json` is extracted from the official STIX bundle
([mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)) by `scripts/build_attack.py`.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

ATT&CK v19 renumbered some techniques (for example T1562.002 "Disable Windows Event Logging" is now part of
T1685.001). Labels are mapped to current ids through ATT&CK's own revoked-by links, and either id is accepted.
