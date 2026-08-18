#!/bin/bash
# Compare local-vs-server hashes for SentinelAI source files
cd /home/kali/SentinelAI
find backend/src frontend/src -type f \( -name '*.js' -o -name '*.jsx' \) | sort | while read -r f; do
  h=$(md5sum "$f" | cut -c1-8)
  echo "$h  $f"
done
