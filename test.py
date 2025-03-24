import requests
import json

# Configuration
API_URL = "http://localhost:8000"
LOGIN_CREDENTIALS = {
    "username": "admin",  # Replace with your admin username
    "password": "admin123"  # Replace with your admin password
}

# Sample books data
SAMPLE_BOOKS = [
    {
        "title": "To Kill a Mockingbird",
        "author": "Harper Lee",
        "isbn": "9780061120084",
        "publication_year": 1960,
        "description": "A classic novel about racism and justice in a small Southern town during the Depression."
    },
    {
        "title": "1984",
        "author": "George Orwell",
        "isbn": "9780451524935",
        "publication_year": 1949,
        "description": "A dystopian novel set in a totalitarian regime where critical thought is suppressed."
    },
    {
        "title": "Pride and Prejudice",
        "author": "Jane Austen",
        "isbn": "9780141439518",
        "publication_year": 1813,
        "description": "A romantic novel about the relationship between Elizabeth Bennet and Mr. Darcy."
    },
    {
        "title": "The Great Gatsby",
        "author": "F. Scott Fitzgerald",
        "isbn": "9780743273565",
        "publication_year": 1925,
        "description": "A novel about the mysterious millionaire Jay Gatsby and his obsession with Daisy Buchanan."
    },
    {
        "title": "The Catcher in the Rye",
        "author": "J.D. Salinger",
        "isbn": "9780316769488",
        "publication_year": 1951,
        "description": "A novel about teenage alienation and loss of innocence."
    },
    {
        "title": "The Hobbit",
        "author": "J.R.R. Tolkien",
        "isbn": "9780618260300",
        "publication_year": 1937,
        "description": "A fantasy novel about the adventures of Bilbo Baggins."
    },
    {
        "title": "Harry Potter and the Philosopher's Stone",
        "author": "J.K. Rowling",
        "isbn": "9780747532743",
        "publication_year": 1997,
        "description": "The first book in the Harry Potter series."
    },
    {
        "title": "The Lord of the Rings",
        "author": "J.R.R. Tolkien",
        "isbn": "9780618640157",
        "publication_year": 1954,
        "description": "An epic fantasy trilogy about the quest to destroy the One Ring."
    },
    {
        "title": "The Hunger Games",
        "author": "Suzanne Collins",
        "isbn": "9780439023481",
        "publication_year": 2008,
        "description": "A dystopian novel about a televised competition where teenagers fight to the death."
    },
    {
        "title": "The Alchemist",
        "author": "Paulo Coelho",
        "isbn": "9780062315007",
        "publication_year": 1988,
        "description": "A philosophical novel about a young shepherd who dreams of finding treasure in Egypt."
    },
    {
        "title": "Brave New World",
        "author": "Aldous Huxley",
        "isbn": "9780060850524",
        "publication_year": 1932,
        "description": "A dystopian novel about a futuristic World State and its citizens."
    },
    {
        "title": "The Kite Runner",
        "author": "Khaled Hosseini",
        "isbn": "9781594631931",
        "publication_year": 2003,
        "description": "A novel about friendship, betrayal, and redemption set in Afghanistan."
    },
    {
        "title": "The Da Vinci Code",
        "author": "Dan Brown",
        "isbn": "9780307474278",
        "publication_year": 2003,
        "description": "A mystery thriller novel about a symbologist who becomes involved in a battle between secret societies."
    },
    {
        "title": "The Shining",
        "author": "Stephen King",
        "isbn": "9780307743657",
        "publication_year": 1977,
        "description": "A horror novel about a family who becomes isolated in a hotel during winter."
    },
    {
        "title": "The Odyssey",
        "author": "Homer",
        "isbn": "9780140268867",
        "publication_year": -800,
        "description": "An ancient Greek epic poem about Odysseus's journey home after the Trojan War."
    },
    {
        "title": "Crime and Punishment",
        "author": "Fyodor Dostoevsky",
        "isbn": "9780486415871",
        "publication_year": 1866,
        "description": "A novel about a poor ex-student who commits a murder and then struggles with guilt."
    },
    {
        "title": "One Hundred Years of Solitude",
        "author": "Gabriel García Márquez",
        "isbn": "9780060883287",
        "publication_year": 1967,
        "description": "A novel about the Buendía family in the fictional town of Macondo."
    },
    {
        "title": "The Handmaid's Tale",
        "author": "Margaret Atwood",
        "isbn": "9780385490818",
        "publication_year": 1985,
        "description": "A dystopian novel set in a future where women are subjugated in a totalitarian society."
    },
    {
        "title": "Frankenstein",
        "author": "Mary Shelley",
        "isbn": "9780486282114",
        "publication_year": 1818,
        "description": "A gothic novel about a scientist who creates a sapient creature in an unorthodox experiment."
    },
    {
        "title": "The Picture of Dorian Gray",
        "author": "Oscar Wilde",
        "isbn": "9780486278070",
        "publication_year": 1890,
        "description": "A philosophical novel about a man whose portrait ages while he remains young."
    }
]

def get_auth_token():
    """Get authentication token by logging in."""
    login_endpoint = f"{API_URL}/token"
    
    # Convert username/password to form data
    form_data = {
        "username": LOGIN_CREDENTIALS["username"],
        "password": LOGIN_CREDENTIALS["password"]
    }
    
    response = requests.post(login_endpoint, data=form_data)
    
    if response.status_code == 200:
        return response.json()["access_token"]
    else:
        print(f"Failed to get auth token: {response.text}")
        return None

def add_books(token):
    """Add sample books to the database."""
    books_endpoint = f"{API_URL}/books/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    
    added_count = 0
    errors = []
    
    for book in SAMPLE_BOOKS:
        response = requests.post(books_endpoint, json=book, headers=headers)
        
        if response.status_code == 201:
            added_count += 1
            print(f"Added: {book['title']} by {book['author']}")
        else:
            errors.append({
                "book": book["title"],
                "error": response.text
            })
            print(f"Failed to add {book['title']}: {response.text}")
    
    return {
        "added_count": added_count,
        "errors": errors
    }

def main():
    """Main function to add sample books."""
    print("Getting authentication token...")
    token = get_auth_token()
    
    if not token:
        print("Failed to authenticate. Make sure the API is running and the credentials are correct.")
        return
    
    print("\nAdding sample books...")
    result = add_books(token)
    
    print(f"\nAdded {result['added_count']} out of {len(SAMPLE_BOOKS)} books.")
    
    if result["errors"]:
        print(f"Encountered {len(result['errors'])} errors:")
        for error in result["errors"]:
            print(f"- {error['book']}: {error['error']}")

if __name__ == "__main__":
    main()