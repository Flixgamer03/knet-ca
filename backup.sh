#!/usr/bin/env bash
# Backs up CA keys, database and settings to backups/knet-ca-<time>.tar.gz
# The archive contains the private CA keys – store it securely (offline/encrypted)!
set -euo pipefail
cd "$(dirname "$0")"
TS="$(date +%Y%m%d-%H%M%S)"
mkdir -p backups
umask 077
# consistent copy of the SQLite database while running
docker compose exec -T ca python -c "import sqlite3; s=sqlite3.connect('/data/ca.sqlite'); d=sqlite3.connect('/data/backup.sqlite'); s.backup(d); d.close()"
docker run --rm -v knet-ca-data:/data:ro -v "$PWD/backups:/b" alpine \
  tar czf "/b/knet-ca-$TS.tar.gz" -C /data --exclude=ca.sqlite --exclude=ca.sqlite-wal --exclude=ca.sqlite-shm .
docker compose exec -T ca rm -f /data/backup.sqlite
cp .env "backups/knet-ca-$TS.env"
echo "✔ Backup: backups/knet-ca-$TS.tar.gz (+ .env)"
