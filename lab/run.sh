#!/usr/bin/env bash
# Starts the vulnerable app on 127.0.0.1:8080 with PHP's built-in server and
# appends every request line to lab/logs/access.log.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p sessions logs app/uploads
echo "Lab listening on http://127.0.0.1:8080 (Ctrl+C to stop). Log: lab/logs/access.log"
exec php -S 127.0.0.1:8080 -t app -d session.save_path="$(pwd)/sessions" 2>&1 | tee -a logs/access.log
