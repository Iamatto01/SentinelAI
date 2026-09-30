#!/bin/bash
# start-all.sh - RETIRED 2026-09-26 (defect N-06). DO NOT RESURRECT.
#
# HISTORICAL DEFECT N-06 - DO NOT REINTRODUCE
# ---------------------------------------------------------------------------
# This script used to be ExecStart of sentinelai.service. It did three harmful
# things, each of which is now owned by a different supervisor:
#
#   1. `pkill -f msfrpcd` + `fuser -k 55553/tcp` -> killed the msfrpcd that
#      sentinelai.service itself owns, defeating systemd process tracking.
#   2. `pkill -f "tunnel.*run sentinelai"` -> killed the cloudflared that
#      PM2 owns (id=4).
#   3. `exec npm run dev` -> started a SECOND copy of FYP2 on ports 5000/5173
#      that PM2 already owned. Result: EADDRINUSE on day one, a duplicate vite
#      squatting port 5174 for 14 days, and PM2's backend SIGKILLed
#      mid-transaction 33,563 times. That is what produced the 4,096-byte,
#      0-table backup files published as fyp2_latest_backup.db - silent,
#      valid-looking, useless backups.
#
# PORT OWNERSHIP - SINGLE SOURCE OF TRUTH
#   PM2                -> 5000 sentinel-backend, 5173 sentinel-frontend,
#                         3010 sentinel-api, 20128 9router, 3005, 8016, 8029
#   sentinelai.service -> 55553 msfrpcd  (and nothing else)
#   cloudflared        -> PM2 id=4
#
# A supervisor killing another supervisor's port is not a restart strategy;
# it is silent data corruption with a scheduler.
# See resources/ARCHIVED-second-supervisor.md
# ---------------------------------------------------------------------------

echo "start-all.sh is RETIRED (defect N-06). It starts nothing by design." >&2
echo "" >&2
echo "  PM2                owns 5000/5173/3010/20128/3005/8016/8029" >&2
echo "                          -> pm2 status" >&2
echo "  sentinelai.service owns 55553 (msfrpcd) only" >&2
echo "                          -> systemctl status sentinelai" >&2
echo "" >&2
echo "  Do not add this script to any systemd unit." >&2
exit 1
