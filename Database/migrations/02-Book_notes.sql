-- Book notes/comments table
CREATE TABLE book_notes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    book_id INTEGER REFERENCES books(id) ON DELETE CASCADE,
    note_text TEXT NOT NULL CHECK (LENGTH(note_text) <= 2000),
    is_private BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (user_id, book_id)
);

-- Indexes for performance
CREATE INDEX idx_book_notes_user_id ON book_notes(user_id);
CREATE INDEX idx_book_notes_book_id ON book_notes(book_id);