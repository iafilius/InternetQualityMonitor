#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIAGRAMS_DIR="$ROOT_DIR/docs/diagrams"
OUTDIR="$ROOT_DIR/docs/images"

if ! command -v plantuml >/dev/null 2>&1; then
  echo "Error: plantuml not found on PATH." >&2
  echo "Install with: brew install plantuml (macOS) or use Docker: make diagrams" >&2
  exit 1
fi

mkdir -p "$OUTDIR"

shopt -s nullglob
files=("$DIAGRAMS_DIR"/*.puml)
if [ ${#files[@]} -eq 0 ]; then
  echo "No .puml files found in $DIAGRAMS_DIR"
  exit 0
fi

echo "Rendering ${#files[@]} diagram(s) to $OUTDIR using local plantuml..."
for f in "${files[@]}"; do
  base="$(basename "${f%.puml}")"
  echo " - $base.puml -> $base.png"
  plantuml -tpng "$f" -o "$OUTDIR"
done

echo "Done. Images are in $OUTDIR"
