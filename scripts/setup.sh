#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IDA_DIR="${1:-${IDADIR:-}}"

if [[ -z "$IDA_DIR" ]]; then
  echo "Usage: bash scripts/setup.sh /path/to/ida" >&2
  echo "   or: IDADIR=/path/to/ida bash scripts/setup.sh" >&2
  exit 1
fi

python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install -U pip
"$ROOT/.venv/bin/pip" install -e "$ROOT"
"$ROOT/.venv/bin/pip" install "$IDA_DIR/idalib/python/idapro-"*.whl
"$ROOT/.venv/bin/python" "$IDA_DIR/idalib/python/py-activate-idalib.py" -d "$IDA_DIR"

echo "Done. Activate with: source $ROOT/.venv/bin/activate"
echo "Start server: python $ROOT/server.py --ida-dir $IDA_DIR"
