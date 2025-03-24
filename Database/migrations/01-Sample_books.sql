-- Insert sample books
INSERT INTO books (title, author, isbn, publication_year, description) VALUES
('To Kill a Mockingbird', 'Harper Lee', '9780061120084', 1960, 'A classic novel about racism and justice in a small Southern town during the Depression.'),
('1984', 'George Orwell', '9780451524935', 1949, 'A dystopian novel set in a totalitarian regime where critical thought is suppressed.'),
('Pride and Prejudice', 'Jane Austen', '9780141439518', 1813, 'A romantic novel about the relationship between Elizabeth Bennet and Mr. Darcy.'),
('The Great Gatsby', 'F. Scott Fitzgerald', '9780743273565', 1925, 'A novel about the mysterious millionaire Jay Gatsby and his obsession with Daisy Buchanan.'),
('The Catcher in the Rye', 'J.D. Salinger', '9780316769488', 1951, 'A novel about teenage alienation and loss of innocence.'),
('The Hobbit', 'J.R.R. Tolkien', '9780618260300', 1937, 'A fantasy novel about the adventures of Bilbo Baggins.'),
('Harry Potter and the Philosopher''s Stone', 'J.K. Rowling', '9780747532743', 1997, 'The first book in the Harry Potter series.'),
('The Lord of the Rings', 'J.R.R. Tolkien', '9780618640157', 1954, 'An epic fantasy trilogy about the quest to destroy the One Ring.'),
('The Hunger Games', 'Suzanne Collins', '9780439023481', 2008, 'A dystopian novel about a televised competition where teenagers fight to the death.'),
('The Alchemist', 'Paulo Coelho', '9780062315007', 1988, 'A philosophical novel about a young shepherd who dreams of finding treasure in Egypt.'),
('Brave New World', 'Aldous Huxley', '9780060850524', 1932, 'A dystopian novel about a futuristic World State and its citizens.'),
('The Kite Runner', 'Khaled Hosseini', '9781594631931', 2003, 'A novel about friendship, betrayal, and redemption set in Afghanistan.'),
('The Da Vinci Code', 'Dan Brown', '9780307474278', 2003, 'A mystery thriller novel about a symbologist who becomes involved in a battle between secret societies.'),
('The Shining', 'Stephen King', '9780307743657', 1977, 'A horror novel about a family who becomes isolated in a hotel during winter.'),
('The Odyssey', 'Homer', '9780140268867', -800, 'An ancient Greek epic poem about Odysseus''s journey home after the Trojan War.'),
('Crime and Punishment', 'Fyodor Dostoevsky', '9780486415871', 1866, 'A novel about a poor ex-student who commits a murder and then struggles with guilt.'),
('One Hundred Years of Solitude', 'Gabriel García Márquez', '9780060883287', 1967, 'A novel about the Buendía family in the fictional town of Macondo.'),
('The Handmaid''s Tale', 'Margaret Atwood', '9780385490818', 1985, 'A dystopian novel set in a future where women are subjugated in a totalitarian society.'),
('Frankenstein', 'Mary Shelley', '9780486282114', 1818, 'A gothic novel about a scientist who creates a sapient creature in an unorthodox experiment.'),
('The Picture of Dorian Gray', 'Oscar Wilde', '9780486278070', 1890, 'A philosophical novel about a man whose portrait ages while he remains young.');

-- Create some genre tags
INSERT INTO tags (name, description) VALUES
('Classic', 'Timeless literature that has stood the test of time'),
('Fantasy', 'Fiction involving magical elements and imaginary worlds'),
('Science Fiction', 'Fiction based on scientific discoveries or advanced technology'),
('Dystopian', 'Fiction set in repressive or post-apocalyptic societies'),
('Romance', 'Fiction focused on romantic relationships'),
('Horror', 'Fiction intended to frighten, scare, or disgust'),
('Mystery', 'Fiction dealing with the solution of a crime or puzzle'),
('Adventure', 'Fiction involving exciting or dangerous experiences');

-- Associate tags with books
INSERT INTO book_tags (book_id, tag_id) VALUES
(1, 1), -- To Kill a Mockingbird: Classic
(2, 1), (2, 3), (2, 4), -- 1984: Classic, Sci-Fi, Dystopian
(3, 1), (3, 5), -- Pride and Prejudice: Classic, Romance
(4, 1), -- The Great Gatsby: Classic
(5, 1), -- The Catcher in the Rye: Classic
(6, 2), (6, 8), -- The Hobbit: Fantasy, Adventure
(7, 2), (7, 8), -- Harry Potter: Fantasy, Adventure
(8, 2), (8, 8), -- The Lord of the Rings: Fantasy, Adventure
(9, 3), (9, 4), (9, 8), -- The Hunger Games: Sci-Fi, Dystopian, Adventure
(10, 8), -- The Alchemist: Adventure
(11, 3), (11, 4), -- Brave New World: Sci-Fi, Dystopian
(12, 1), -- The Kite Runner: Classic
(13, 7), (13, 8), -- The Da Vinci Code: Mystery, Adventure
(14, 6), -- The Shining: Horror
(15, 1), (15, 8), -- The Odyssey: Classic, Adventure
(16, 1), (16, 7), -- Crime and Punishment: Classic, Mystery
(17, 1), -- One Hundred Years of Solitude: Classic
(18, 3), (18, 4), -- The Handmaid's Tale: Sci-Fi, Dystopian
(19, 1), (19, 6), -- Frankenstein: Classic, Horror
(20, 1); -- The Picture of Dorian Gray: Classic