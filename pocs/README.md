# PoC bundles

Runnable, self-contained proof-of-concept bundles — **one folder per plugin, one
subfolder per finding**:

```
pocs/<slug>/<finding-id>/
  docker-compose.yml   WordPress + MariaDB + the pinned plugin version
  poc.py               brings the stack up, runs the exploit, prints a verdict, tears down
  README.md            two-command manual repro
  plugin/              the exact plugin source under test (pinned, so it repros later)
  finding.json         the finding metadata
```

The pipeline scaffolds one for **every HIGH/CRITICAL finding** (see
[`opt/wp_workflow.md`](../opt/wp_workflow.md) §8):
```bash
python scripts/wp_poc.py scaffold --slug <slug> --id <finding-id>
```

Reproduce any finding with just Docker:
```bash
cd pocs/<slug>/<finding-id> && python poc.py
```
Exit `0` = reproduced · `1` = not reproduced · `2` = sandbox failed to boot.

Generated bundles are gitignored (`/pocs/*/`) because each carries a plugin source
copy — the repo stays code-only. **Authorised testing only**, against a private
instance you control.
