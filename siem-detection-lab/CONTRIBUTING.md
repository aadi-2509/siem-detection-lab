# Contributing

## Adding a new rule

1. Create a new `.xml` file in the correct tactic folder under `rules/`
2. Use the next available ID in the 1001xx–1006xx range
3. Add a MITRE ATT&CK technique ID in the `<mitre>` block
4. Write at least one test in `tests/test_rules.py`
5. Add a comment block at the top explaining why the rule exists and how the threshold was chosen
6. Update `README.md` rule table and `CHANGELOG.md`

## Rule ID ranges

| Range       | Tactic             |
|-------------|--------------------|
| 100100–100199 | Credential Access |
| 100200–100299 | Lateral Movement  |
| 100300–100399 | Persistence       |
| 100400–100499 | Defense Evasion   |
| 100500–100599 | Exfiltration      |
| 100600–100699 | Discovery         |

## Running tests

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest tests/ -v
```

## Commit style

```
feat(rules): add kernel module load from /tmp detection (T1547.006)
fix(rules): raise SSH brute force threshold to reduce alert fatigue
test(api): add coverage for replay endpoint edge cases
```
