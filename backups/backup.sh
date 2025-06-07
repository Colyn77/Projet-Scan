#!/bin/bash

# Variables
DB_NAME="scan_results"
DB_USER="scan_user"
BACKUP_DIR="backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="$BACKUP_DIR/${DB_NAME}_backup_$TIMESTAMP.sql"

# Sauvegarde
mkdir -p "$BACKUP_DIR"
pg_dump -U "$DB_USER" -F p -d "$DB_NAME" > "$FILENAME"

if [ $? -eq 0 ]; then
    echo "✅ Backup created: $FILENAME"
else
    echo "❌ Backup failed"
fi
