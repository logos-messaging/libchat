#!/bin/bash
set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <file1> <file2>" >&2
    exit 1
fi

FILE1="$1"
FILE2="$2"
SCRIPTS="$(dirname "$0")"

NORM1=$(python3 "$SCRIPTS/normalize_logs.py" < "$FILE1")
NORM2=$(python3 "$SCRIPTS/normalize_logs.py" < "$FILE2")

ALIGNED2=$(python3 "$SCRIPTS/align_logs.py" <(echo "$NORM1") <(echo "$NORM2") 2>/dev/null)

echo "$NORM1" > "$FILE1"
echo "$ALIGNED2" > "$FILE2"
