#!/usr/bin/env bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "[C Engine] Building..."
gcc -O2 -shared -fPIC -lm -o "$DIR/libheuristic.so" "$DIR/heuristic_engine.c"
echo "[C Engine] libheuristic.so done."
