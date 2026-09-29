# Setup

No dependencies beyond the standard library and PyYAML.

```bash
unzip mcp-gateway.zip
cd mcp-gateway
python3 -m pip install pyyaml
./check.sh
```

If `./check.sh` is not executable: `bash check.sh`.

Everything must be run from the repo root with `PYTHONPATH=.` — the packages
import each other by path (`gateway.proxy`, `harness.agent`). `check.sh` sets
this for you. Running a file from inside its own folder will fail with
`ModuleNotFoundError`, and that is expected, not a bug.

## Python version

Built and tested on 3.12, and kept free of private asyncio API so it runs on
3.13 and 3.14. Minimum is 3.10.

## First thing to do

```bash
git init
git add .
git commit -m "week 1-2: proxy, audit log, vulnerable servers, s01 lands"
```

The commit history is part of what this project demonstrates. A reviewer
watching the exploit land in week 2 and the defence land in week 4 reads very
differently from one giant initial commit.
