#!/bin/bash

echo "Waiting for database to be ready..."
pg_isready -h db -U postgres -d booklover -t 60

echo "Checking for book_notes table..."
PGPASSWORD=postgres psql -h db -U postgres -d booklover -c "CREATE TABLE IF NOT EXISTS book_notes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    book_id INTEGER REFERENCES books(id) ON DELETE CASCADE,
    note_text TEXT NOT NULL CHECK (LENGTH(note_text) <= 2000),
    is_private BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (user_id, book_id)
);" || echo "Failed to create book_notes table, continuing anyway"

echo "Creating indexes if they do not exist..."
PGPASSWORD=postgres psql -h db -U postgres -d booklover -c "CREATE INDEX IF NOT EXISTS idx_book_notes_user_id ON book_notes(user_id);" || echo "Failed to create index 1"
PGPASSWORD=postgres psql -h db -U postgres -d booklover -c "CREATE INDEX IF NOT EXISTS idx_book_notes_book_id ON book_notes(book_id);" || echo "Failed to create index 2"

echo "Starting API server..."
uvicorn main:app --host 0.0.0.0 --port 8000 --reload