# Nightwatch

**A SOC copilot: a team of AI agents that investigates real Windows attack recordings and maps them to MITRE ATT&CK,
with every finding quoted from the logs and checked by code.**

Work in progress. Results, the live demo and the full write-up will follow.

- Data: 105 real recordings from OTRF Security-Datasets (1,000 to 60,000 Windows events each), labelled with
  ATT&CK techniques. See [DATA.md](DATA.md).
- Built with Google's Agent Development Kit (ADK 2 Workflow graph), Claude Haiku 4.5, BM25 retrieval over
  ATT&CK v19, and code verification of every quote.

```bash
pip install -r requirements.txt
python -m pytest -q                                   # offline, scripted model, no key
python scripts/run.py --system nightwatch --split dev --limit 5 --model fake --run-id offline-check
```
