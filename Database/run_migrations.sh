#!/bin/bash

# Get the database URL from environment variable or use default
DATABASE_URL=${DATABASE_URL:-"postgresql://postgres:postgres@db:5432/booklover"}

# Extract connection details from the URL
USER=$(echo $DATABASE_URL | sed -n 's/.*:\/\/\([^:]*\):.*/\1/p')
PASSWORD=$(echo $DATABASE_URL | sed -n 's/.*:\/\/[^:]*:\([^@]*\).*/\1/p')
HOST=$(echo $DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
PORT=$(echo $DATABASE_URL | sed -n 's/.*:\([^\/]*\)\/.*/\1/p')
DB=$(echo $DATABASE_URL | sed -n 's/.*\/\(.*\)/\1/p')

echo "Running database migrations..."

# Run migrations in order
for migration in /app/migrations/*.sql; do
  echo "Applying migration: $(basename "$migration")"
  PGPASSWORD=$PASSWORD psql -h $HOST -p $PORT -U $USER -d $DB -f "$migration"
done

echo "All migrations completed successfully."