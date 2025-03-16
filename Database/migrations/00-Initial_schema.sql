CREATE TABLE tags
(
    name        varchar(20) PRIMARY KEY,
    description varchar(1000)
);

-- Many-to-many tag relationships
create table book_tags
(
    tag  varchar(20) REFERENCES tags (name),
    book integer REFERENCES books (id)
);

create table review_tags
(
    tag    varchar(20) REFERENCES tags (name),
    review integer REFERENCES reviews (id)
);
--

CREATE TABLE books
(
    -- Not all books that we might want in the database will have an ISBN
    -- Therefore there must be a separate id column for identifying books.
    id          integer PRIMARY KEY,
    author      integer REFERENCES authors (id),
    isbn        varchar(13),
    title       varchar NOT NULL,
    description varchar
);

CREATE TABLE authors
(
    id   integer PRIMARY KEY,
    name varchar
);

CREATE TABLE users
(
    username varchar(20) PRIMARY KEY,
    email    varchar(320),
    password bytea
);

CREATE TABLE reviews
(
    id     integer PRIMARY KEY,
    book   integer REFERENCES books (id),
    rating integer CHECK (rating >= 0 AND rating <= 5),
    body   varchar(1000)
);