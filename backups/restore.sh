#!/bin/bash

# Variables
DB_NAME="scan_results"
DB_USER="scan_user"
BACKUP_FILE=$1

# Vérification
if [ -z "$BACKUP_FILE" ]; then
    echo "❌ Please provide a backup file."
    echo "Usage: $0 backups/scan_results_backup_YYYYMMDD_HHMMSS.sql"
    exit 1
fi

# Restauration
psql -U "$DB_USER" -d "$DB_NAME" < "$BACKUP_FILE"

if [ $? -eq 0 ]; then
    echo "✅ Database restored from $BACKUP_FILE"
else
    echo "❌ Restore failed"
fi
