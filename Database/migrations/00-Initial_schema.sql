-- Initial schema for 4BookLovers application

-- Tags table
CREATE TABLE tags (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(1000)
);

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE
);

-- User sessions
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    device_info TEXT
);

-- Create a trigger function to enforce max sessions per user
CREATE OR REPLACE FUNCTION check_max_sessions()
RETURNS TRIGGER AS $$
BEGIN
    IF (SELECT COUNT(*) FROM sessions 
        WHERE user_id = NEW.user_id 
        AND expires_at > CURRENT_TIMESTAMP) > 5 THEN
        RAISE EXCEPTION 'User cannot have more than 5 active sessions';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_max_sessions
BEFORE INSERT OR UPDATE ON sessions
FOR EACH ROW EXECUTE FUNCTION check_max_sessions();

-- Books table
CREATE TABLE books (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    author VARCHAR(255) NOT NULL,
    isbn VARCHAR(20) UNIQUE,
    publisher VARCHAR(100),
    publication_year INTEGER,
    description TEXT,
    cover_image_url TEXT,
    page_count INTEGER,
    language VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Book-Tags relationship
CREATE TABLE book_tags (
    book_id INTEGER REFERENCES books(id) ON DELETE CASCADE,
    tag_id INTEGER REFERENCES tags(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (book_id, tag_id)
);

-- Function to enforce max tags per book
CREATE OR REPLACE FUNCTION check_max_tags_per_book()
RETURNS TRIGGER AS $$
BEGIN
    IF (SELECT COUNT(*) FROM book_tags WHERE book_id = NEW.book_id) > 50 THEN
        RAISE EXCEPTION 'Book cannot have more than 50 tags';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_max_tags_per_book
BEFORE INSERT ON book_tags
FOR EACH ROW EXECUTE FUNCTION check_max_tags_per_book();

-- Reading shelves
CREATE TABLE shelves (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, name)
);

-- Function to enforce max custom shelves per user
CREATE OR REPLACE FUNCTION check_max_custom_shelves()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.is_default = FALSE AND
       (SELECT COUNT(*) FROM shelves 
        WHERE user_id = NEW.user_id AND is_default = FALSE) > 20 THEN
        RAISE EXCEPTION 'User cannot have more than 20 custom shelves';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_max_custom_shelves
BEFORE INSERT ON shelves
FOR EACH ROW EXECUTE FUNCTION check_max_custom_shelves();

-- Books on shelves
CREATE TABLE shelf_books (
    shelf_id INTEGER REFERENCES shelves(id) ON DELETE CASCADE,
    book_id INTEGER REFERENCES books(id) ON DELETE CASCADE,
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (shelf_id, book_id)
);

-- Function to enforce max books per shelf
CREATE OR REPLACE FUNCTION check_max_books_per_shelf()
RETURNS TRIGGER AS $$
BEGIN
    IF (SELECT COUNT(*) FROM shelf_books WHERE shelf_id = NEW.shelf_id) > 350 THEN
        RAISE EXCEPTION 'Shelf cannot have more than 350 books';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_max_books_per_shelf
BEFORE INSERT ON shelf_books
FOR EACH ROW EXECUTE FUNCTION check_max_books_per_shelf();

-- Reviews
CREATE TABLE reviews (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    book_id INTEGER REFERENCES books(id) ON DELETE CASCADE,
    rating INTEGER CHECK (rating BETWEEN 1 AND 5),
    review_text TEXT CHECK (LENGTH(review_text) <= 1000),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (user_id, book_id)
);

-- Default shelves for all users
INSERT INTO shelves (name, description, is_default) VALUES
    ('Want to Read', 'Books you want to read', TRUE),
    ('Currently Reading', 'Books you are currently reading', TRUE),
    ('Read', 'Books you have finished reading', TRUE);

-- Indexes for performance
CREATE INDEX idx_book_tags_book_id ON book_tags(book_id);
CREATE INDEX idx_book_tags_tag_id ON book_tags(tag_id);
CREATE INDEX idx_shelf_books_shelf_id ON shelf_books(shelf_id);
CREATE INDEX idx_shelf_books_book_id ON shelf_books(book_id);
CREATE INDEX idx_reviews_user_id ON reviews(user_id);
CREATE INDEX idx_reviews_book_id ON reviews(book_id);
CREATE INDEX idx_shelves_user_id ON shelves(user_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);