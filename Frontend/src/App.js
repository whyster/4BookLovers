import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import { Container, Alert } from 'react-bootstrap';
import axios from 'axios';
import 'bootstrap/dist/css/bootstrap.min.css';

// api configuration with base url and default headers
const API_URL = 'http://localhost:8000';
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// auth context for managing user authentication state throughout the app
const AuthContext = React.createContext(null);

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  // load user on mount and when token changes
  useEffect(() => {
    const loadUser = async () => {
      if (token) {
        try {
          api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
          const { data } = await api.get('/users/me');
          setUser(data);
        } catch (error) {
          console.error('Error loading user:', error);
          localStorage.removeItem('token');
          setToken(null);
          setUser(null);
        }
      }
      setLoading(false);
    };

    loadUser();
  }, [token]);

  // login function to authenticate user with username and password
  const login = async (username, password) => {
    try {
      const formData = new FormData();
      formData.append('username', username);
      formData.append('password', password);
      
      const { data } = await axios.post(`${API_URL}/token`, formData);
      
      if (data.access_token) {
        localStorage.setItem('token', data.access_token);
        setToken(data.access_token);
        api.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`;
        
        // get user data after successful login
        const { data: userData } = await api.get('/users/me');
        setUser(userData);
        
        return { success: true };
      }
    } catch (error) {
      console.error('Login error:', error);
      return { 
        success: false, 
        message: error.response?.data?.detail || 'Login failed. Please check your credentials.' 
      };
    }
  };

  // register function to create new user account
  const register = async (userData) => {
    try {
      const { data } = await api.post('/users/', userData);
      return { success: true };
    } catch (error) {
      console.error('Register error:', error);
      return { 
        success: false, 
        message: error.response?.data?.detail || 'Registration failed. Please try again.' 
      };
    }
  };

  // logout function to clear user session
  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    delete api.defaults.headers.common['Authorization'];
  };

  // helper function to check if user is authenticated
  const isAuthenticated = () => {
    return !!token && !!user;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        register,
        logout,
        isAuthenticated,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

// navigation component with conditional rendering based on auth state
const Navigation = () => {
  const auth = React.useContext(AuthContext);
  
  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-dark">
      <div className="container">
        <Link className="navbar-brand" to="/">4BookLovers</Link>
        <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarNav">
          <ul className="navbar-nav ms-auto">
            {auth.isAuthenticated() ? (
              <>
                <li className="nav-item">
                  <Link className="nav-link" to="/dashboard">My Books</Link>
                </li>
                <li className="nav-item">
                  <span className="nav-link" style={{ cursor: 'pointer' }} onClick={auth.logout}>
                    Logout ({auth.user?.username})
                  </span>
                </li>
              </>
            ) : (
              <>
                <li className="nav-item">
                  <Link className="nav-link" to="/login">Login</Link>
                </li>
                <li className="nav-item">
                  <Link className="nav-link" to="/register">Register</Link>
                </li>
              </>
            )}
          </ul>
        </div>
      </div>
    </nav>
  );
};

const Footer = () => (
  <footer className="bg-dark text-light py-3 mt-auto">
    <div className="container text-center">
      <p className="mb-0">© 2025 4BookLovers - A platform for book enthusiasts</p>
    </div>
  </footer>
);

// home page with static content for unauthenticated users
const Home = () => (
  <div className="text-center my-5">
    <h1>Welcome to 4BookLovers</h1>
    <p className="lead">Discover, track, and share your reading journey</p>
    <div className="my-4">
      <h2>Popular Books</h2>
      <div className="row justify-content-center">
        {['The Great Gatsby', 'To Kill a Mockingbird', 'Pride and Prejudice'].map(book => (
          <div key={book} className="col-md-3 mb-4">
            <div className="card">
              <div className="card-body">
                <h5 className="card-title">{book}</h5>
                <p className="card-text">A classic novel loved by readers worldwide.</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  </div>
);

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const auth = React.useContext(AuthContext);
  
  // redirect to dashboard if already logged in
  if (auth.isAuthenticated()) {
    return <Navigate to="/dashboard" />;
  }
  
  // handle login form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    
    const result = await auth.login(username, password);
    setIsLoading(false);
    
    if (!result.success) {
      setError(result.message);
    }
  };
  
  return (
    <div className="row justify-content-center my-5">
      <div className="col-md-6">
        <div className="card">
          <div className="card-header">
            <h3 className="text-center">Login</h3>
          </div>
          <div className="card-body">
            {error && <Alert variant="danger">{error}</Alert>}
            <form onSubmit={handleSubmit}>
              <div className="mb-3">
                <label htmlFor="username" className="form-label">Username</label>
                <input 
                  type="text" 
                  className="form-control" 
                  id="username" 
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                />
              </div>
              <div className="mb-3">
                <label htmlFor="password" className="form-label">Password</label>
                <input 
                  type="password" 
                  className="form-control" 
                  id="password" 
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
              <button 
                type="submit" 
                className="btn btn-primary w-100" 
                disabled={isLoading}
              >
                {isLoading ? 'Logging in...' : 'Login'}
              </button>
            </form>
            <div className="mt-3 text-center">
              <p>Don't have an account? <Link to="/register">Register here</Link></p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const Register = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const auth = React.useContext(AuthContext);
  
  // redirect to dashboard if already logged in
  if (auth.isAuthenticated()) {
    return <Navigate to="/dashboard" />;
  }
  
  // handle form input changes
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };
  
  // handle registration form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    setSuccess('');
    
    // validate passwords match
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      setIsLoading(false);
      return;
    }
    
    // validate password length
    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters long');
      setIsLoading(false);
      return;
    }
    
    const userData = {
      username: formData.username,
      email: formData.email,
      password: formData.password
    };
    
    const result = await auth.register(userData);
    setIsLoading(false);
    
    if (result.success) {
      setSuccess('Registration successful! You can now log in.');
      setFormData({
        username: '',
        email: '',
        password: '',
        confirmPassword: ''
      });
    } else {
      setError(result.message);
    }
  };
  
  return (
    <div className="row justify-content-center my-5">
      <div className="col-md-6">
        <div className="card">
          <div className="card-header">
            <h3 className="text-center">Register</h3>
          </div>
          <div className="card-body">
            {error && <Alert variant="danger">{error}</Alert>}
            {success && <Alert variant="success">{success}</Alert>}
            <form onSubmit={handleSubmit}>
              <div className="mb-3">
                <label htmlFor="username" className="form-label">Username</label>
                <input 
                  type="text" 
                  className="form-control" 
                  id="username" 
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="mb-3">
                <label htmlFor="email" className="form-label">Email</label>
                <input 
                  type="email" 
                  className="form-control" 
                  id="email" 
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="mb-3">
                <label htmlFor="password" className="form-label">Password</label>
                <input 
                  type="password" 
                  className="form-control" 
                  id="password" 
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  required
                />
                <small className="text-muted">Password must be at least 8 characters long</small>
              </div>
              <div className="mb-3">
                <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
                <input 
                  type="password" 
                  className="form-control" 
                  id="confirmPassword" 
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  required
                />
              </div>
              <button 
                type="submit" 
                className="btn btn-primary w-100"
                disabled={isLoading}
              >
                {isLoading ? 'Registering...' : 'Register'}
              </button>
            </form>
            <div className="mt-3 text-center">
              <p>Already have an account? <Link to="/login">Login here</Link></p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// modal component for adding new books
const AddBookModal = ({ show, handleClose, handleAddBook }) => {
  const [formData, setFormData] = useState({
    title: '',
    author: '',
    isbn: '',
    publication_year: '',
    description: ''
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  // handle form input changes
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  // handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      await handleAddBook(formData);
      handleClose();
    } catch (error) {
      setError(error.message || 'Failed to add book');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={`modal ${show ? 'd-block' : 'd-none'}`} tabIndex="-1" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
      <div className="modal-dialog modal-dialog-centered">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">Add New Book</h5>
            <button type="button" className="btn-close" onClick={handleClose}></button>
          </div>
          <div className="modal-body">
            {error && <Alert variant="danger">{error}</Alert>}
            <form onSubmit={handleSubmit}>
              <div className="mb-3">
                <label htmlFor="title" className="form-label">Title *</label>
                <input 
                  type="text" 
                  className="form-control" 
                  id="title" 
                  name="title"
                  value={formData.title}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="mb-3">
                <label htmlFor="author" className="form-label">Author *</label>
                <input 
                  type="text" 
                  className="form-control" 
                  id="author" 
                  name="author"
                  value={formData.author}
                  onChange={handleChange}
                  required
                />
              </div>
              <div className="mb-3">
                <label htmlFor="isbn" className="form-label">ISBN</label>
                <input 
                  type="text" 
                  className="form-control" 
                  id="isbn" 
                  name="isbn"
                  value={formData.isbn}
                  onChange={handleChange}
                />
              </div>
              <div className="mb-3">
                <label htmlFor="publication_year" className="form-label">Publication Year</label>
                <input 
                  type="number" 
                  className="form-control" 
                  id="publication_year" 
                  name="publication_year"
                  value={formData.publication_year}
                  onChange={handleChange}
                />
              </div>
              <div className="mb-3">
                <label htmlFor="description" className="form-label">Description</label>
                <textarea 
                  className="form-control" 
                  id="description" 
                  name="description"
                  rows="3"
                  value={formData.description}
                  onChange={handleChange}
                ></textarea>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={handleClose}>Close</button>
                <button type="submit" className="btn btn-primary" disabled={isLoading}>
                  {isLoading ? 'Adding...' : 'Add Book'}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

// modal component for adding or editing book notes
const BookNoteModal = ({ show, handleClose, bookId, bookTitle, existingNote, handleSaveNote }) => {
  const [formData, setFormData] = useState({
    note_text: existingNote?.note_text || '',
    is_private: existingNote?.is_private !== false // default to private if no existing note or existing is private
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  // reset form when the modal is shown with different data
  useEffect(() => {
    if (show) {
      setFormData({
        note_text: existingNote?.note_text || '',
        is_private: existingNote?.is_private !== false
      });
      setError('');
    }
  }, [show, existingNote]);

  // handle form input changes
  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({ 
      ...prev, 
      [name]: type === 'checkbox' ? checked : value 
    }));
  };

  // handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      await handleSaveNote({
        book_id: bookId,
        note_text: formData.note_text,
        is_private: formData.is_private
      });
      handleClose();
    } catch (error) {
      setError(error.message || 'Failed to save note');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={`modal ${show ? 'd-block' : 'd-none'}`} tabIndex="-1" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
      <div className="modal-dialog modal-dialog-centered">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">{existingNote ? 'Edit' : 'Add'} Note for "{bookTitle}"</h5>
            <button type="button" className="btn-close" onClick={handleClose}></button>
          </div>
          <div className="modal-body">
            {error && <Alert variant="danger">{error}</Alert>}
            <form onSubmit={handleSubmit}>
              <div className="mb-3">
                <label htmlFor="note_text" className="form-label">Your Notes</label>
                <textarea 
                  className="form-control" 
                  id="note_text" 
                  name="note_text"
                  rows="6"
                  value={formData.note_text}
                  onChange={handleChange}
                  placeholder="Add your personal notes, thoughts, or reminders about this book..."
                  required
                ></textarea>
                <small className="text-muted">Maximum 2000 characters</small>
              </div>
              <div className="mb-3 form-check">
                <input 
                  type="checkbox" 
                  className="form-check-input" 
                  id="is_private" 
                  name="is_private"
                  checked={formData.is_private}
                  onChange={handleChange}
                />
                <label className="form-check-label" htmlFor="is_private">Keep this note private</label>
                <small className="form-text d-block text-muted">Uncheck to make your notes visible to other users</small>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={handleClose}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={isLoading}>
                  {isLoading ? 'Saving...' : 'Save Note'}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

// main dashboard component for authenticated users
const Dashboard = () => {
  const auth = React.useContext(AuthContext);
  const [books, setBooks] = useState([]);
  const [shelves, setShelves] = useState([]);
  const [selectedShelf, setSelectedShelf] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  
  // book notes state
  const [showNoteModal, setShowNoteModal] = useState(false);
  const [selectedBook, setSelectedBook] = useState(null);
  const [currentNote, setCurrentNote] = useState(null);
  const [loadingNote, setLoadingNote] = useState(false);
  
  // fetch shelves when the component mounts
  useEffect(() => {
    if (auth.isAuthenticated()) {
      const fetchShelves = async () => {
        try {
          const response = await api.get('/shelves/');
          setShelves(response.data);
        } catch (err) {
          console.error('Error fetching shelves:', err);
        }
      };
      
      fetchShelves();
    }
  }, [auth]);

  // function to fetch all books
  const fetchAllBooks = async () => {
    setLoading(true);
    try {
      const response = await api.get('/books/');
      setBooks(response.data);
      setError('');
    } catch (err) {
      console.error('Error fetching books:', err);
      setError('Failed to load books. Please try again later.');
    } finally {
      setLoading(false);
    }
  };
  
  // function to fetch books by shelf
  const fetchBooksByShelf = async (shelf) => {
    setLoading(true);
    try {
      const response = await api.get(`/shelves/${shelf.id}/books`);
      setBooks(response.data);
      setError('');
    } catch (err) {
      console.error('Error fetching books for shelf:', err);
      setError(`Failed to load books for shelf "${shelf.name}". Please try again later.`);
    } finally {
      setLoading(false);
    }
  };
  
  // function to search books by title, author, or isbn
  const searchBooks = async (query) => {
    setLoading(true);
    setIsSearching(true);
    try {
      const response = await api.get(`/books/?query=${encodeURIComponent(query)}`);
      setBooks(response.data);
      setError('');
    } catch (err) {
      console.error('Error searching books:', err);
      setError('Failed to search books. Please try again later.');
    } finally {
      setLoading(false);
    }
  };
  
  // handle search input change
  const handleSearchChange = (e) => {
    const query = e.target.value;
    setSearchQuery(query);
  };
  
  // handle search form submission
  const handleSearch = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      searchBooks(searchQuery);
    } else {
      setIsSearching(false);
      if (selectedShelf) {
        fetchBooksByShelf(selectedShelf);
      } else {
        fetchAllBooks();
      }
    }
  };
  
  // fetch books based on the selected shelf or all books
  useEffect(() => {
    if (auth.isAuthenticated()) {
      if (isSearching && searchQuery.trim()) {
        searchBooks(searchQuery);
      } else if (selectedShelf) {
        fetchBooksByShelf(selectedShelf);
      } else {
        fetchAllBooks();
      }
    }
  }, [selectedShelf, showAddModal, auth, isSearching]); // re-fetch when shelf changes, modal is closed, auth changes, or search status changes
  
  // redirect if not authenticated
  if (!auth.isAuthenticated()) {
    return <Navigate to="/login" />;
  }
  
  // function to add a new book
  const handleAddBook = async (bookData) => {
    try {
      const response = await api.post('/books/', bookData);
      if (!selectedShelf) {
        // only update the books list if we're viewing all books
        setBooks(prevBooks => [...prevBooks, response.data]);
      }
      return response.data;
    } catch (error) {
      console.error('Error adding book:', error);
      throw new Error(error.response?.data?.detail || 'Failed to add book');
    }
  };

  // function to add a book to a shelf
  const handleAddToShelf = async (bookId, shelfName) => {
    try {
      // find the shelf id by name
      const shelf = shelves.find(s => s.name === shelfName);
      if (shelf) {
        await api.post(`/shelves/${shelf.id}/books/${bookId}`);
        alert(`Added book to "${shelfName}" shelf!`);
        
        // refresh books if viewing the shelf we just added to
        if (selectedShelf && selectedShelf.id === shelf.id) {
          fetchBooksByShelf(shelf);
        }
      } else {
        alert(`Shelf "${shelfName}" not found`);
      }
    } catch (error) {
      console.error('Error adding to shelf:', error);
      alert(`Error adding to shelf: ${error.response?.data?.detail || error.message}`);
    }
  };
  
  // function to remove a book from the current shelf
  const handleRemoveFromShelf = async (bookId) => {
    try {
      // only proceed if a shelf is selected
      if (!selectedShelf) {
        return;
      }
      
      await api.delete(`/shelves/${selectedShelf.id}/books/${bookId}`);
      
      // remove the book from the local state to update ui immediately
      setBooks(prevBooks => prevBooks.filter(book => book.id !== bookId));
      
      alert(`Removed book from "${selectedShelf.name}" shelf!`);
    } catch (error) {
      console.error('Error removing from shelf:', error);
      alert(`Error removing from shelf: ${error.response?.data?.detail || error.message}`);
    }
  };

  // handle shelf selection
  const handleShelfClick = (shelf) => {
    setSelectedShelf(shelf);
  };

  // handle showing all books
  const handleShowAllBooks = () => {
    setSelectedShelf(null);
    setIsSearching(false);
    setSearchQuery('');
  };
  
  // clear search and show all books or shelf books
  const handleClearSearch = () => {
    setSearchQuery('');
    setIsSearching(false);
    if (selectedShelf) {
      fetchBooksByShelf(selectedShelf);
    } else {
      fetchAllBooks();
    }
  };
  
  // function to handle clicking the add/edit note button
  const handleNoteClick = async (book) => {
    setSelectedBook(book);
    setLoadingNote(true);
    
    try {
      // try to get an existing note for this book
      const response = await api.get(`/book-notes/${book.id}`);
      setCurrentNote(response.data);
    } catch (error) {
      // if note doesn't exist, set to null (will create a new one)
      if (error.response && error.response.status === 404) {
        setCurrentNote(null);
      } else {
        console.error('Error fetching note:', error);
      }
    } finally {
      setLoadingNote(false);
      setShowNoteModal(true);
    }
  };
  
  // function to save a note
  const handleSaveNote = async (noteData) => {
    try {
      const response = await api.post('/book-notes/', noteData);
      
      // if we're looking at a specific shelf, refresh the books
      if (selectedShelf) {
        await fetchBooksByShelf(selectedShelf);
      } else if (isSearching) {
        await searchBooks(searchQuery);
      } else {
        await fetchAllBooks();
      }
      
      return response.data;
    } catch (error) {
      console.error('Error saving note:', error);
      throw new Error(error.response?.data?.detail || 'Failed to save note');
    }
  };
  
  // function to delete a note
  const handleDeleteNote = async (bookId) => {
    if (window.confirm('Are you sure you want to delete this note?')) {
      try {
        await api.delete(`/book-notes/${bookId}`);
        
        // refresh books list after deletion
        if (selectedShelf) {
          await fetchBooksByShelf(selectedShelf);
        } else if (isSearching) {
          await searchBooks(searchQuery);
        } else {
          await fetchAllBooks();
        }
        
        alert('Note deleted successfully');
      } catch (error) {
        console.error('Error deleting note:', error);
        alert(`Failed to delete note: ${error.response?.data?.detail || error.message}`);
      }
    }
  };
  
  return (
    <div className="my-5">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1>Welcome, {auth.user?.username}!</h1>
        <button 
          className="btn btn-primary" 
          onClick={() => setShowAddModal(true)}
        >
          Add New Book
        </button>
      </div>
      
      <div className="mb-4">
        <form onSubmit={handleSearch} className="d-flex">
          <input
            type="text"
            className="form-control me-2"
            placeholder="Search books by title, author, or ISBN..."
            value={searchQuery}
            onChange={handleSearchChange}
          />
          <button type="submit" className="btn btn-outline-primary me-2">Search</button>
          {isSearching && (
            <button 
              type="button" 
              className="btn btn-outline-secondary"
              onClick={handleClearSearch}
            >
              Clear
            </button>
          )}
        </form>
      </div>
      
      <div className="row mt-4">
        <div className="col-md-4">
          <div className="card">
            <div className="card-header">
              <h4>My Shelves</h4>
            </div>
            <div className="card-body">
              <ul className="list-group">
                <li 
                  className={`list-group-item ${!selectedShelf ? 'active' : ''}`}
                  style={{ cursor: 'pointer' }}
                  onClick={handleShowAllBooks}
                >
                  All Books
                </li>
                {shelves.map(shelf => (
                  <li 
                    key={shelf.id} 
                    className={`list-group-item ${selectedShelf?.id === shelf.id ? 'active' : ''}`}
                    style={{ cursor: 'pointer' }}
                    onClick={() => handleShelfClick(shelf)}
                  >
                    {shelf.name}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
        <div className="col-md-8">
          <div className="card">
            <div className="card-header">
              <h4>
                {isSearching 
                  ? `Search results for "${searchQuery}"` 
                  : selectedShelf 
                    ? `Books in "${selectedShelf.name}"` 
                    : 'All Books'
                }
              </h4>
            </div>
            <div className="card-body">
              {loading ? (
                <p>Loading books...</p>
              ) : error ? (
                <Alert variant="danger">{error}</Alert>
              ) : books.length === 0 ? (
                <p>{isSearching
                  ? `No books found matching "${searchQuery}".`
                  : selectedShelf 
                    ? `You don't have any books in the "${selectedShelf.name}" shelf yet.` 
                    : "You haven't added any books yet. Click \"Add New Book\" to get started!"}</p>
              ) : (
                <div className="list-group">
                  {books.map(book => (
                    <div key={book.id} className="list-group-item list-group-item-action">
                      <div className="d-flex w-100 justify-content-between">
                        <h5 className="mb-1">{book.title}</h5>
                        <div>
                          {selectedShelf && (
                            <button 
                              className="btn btn-sm btn-outline-danger me-2" 
                              onClick={() => handleRemoveFromShelf(book.id)}
                              title={`Remove from ${selectedShelf.name}`}
                            >
                              ✕ Remove from shelf
                            </button>
                          )}
                          <small>{book.publication_year}</small>
                        </div>
                      </div>
                      <p className="mb-1">by {book.author}</p>
                      
                      <div className="d-flex justify-content-between align-items-center mt-2">
                        <button 
                          className="btn btn-sm btn-outline-info" 
                          onClick={() => handleNoteClick(book)}
                          title="Add or edit your notes for this book"
                        >
                          📝 {book.has_note ? 'Edit Note' : 'Add Note'}
                        </button>
                        
                        <div>
                          {!selectedShelf ? (
                            <div className="d-inline">
                              <small className="text-muted me-2">Add to shelf:</small>
                              {shelves.map(shelf => (
                                <button 
                                  key={shelf.id}
                                  className="btn btn-sm btn-outline-primary me-1" 
                                  onClick={() => handleAddToShelf(book.id, shelf.name)}
                                >
                                  {shelf.name}
                                </button>
                              ))}
                            </div>
                          ) : (
                            <div className="d-inline">
                              <small className="text-muted me-2">Add to another shelf:</small>
                              {shelves
                                .filter(shelf => shelf.id !== selectedShelf.id)
                                .map(shelf => (
                                  <button 
                                    key={shelf.id}
                                    className="btn btn-sm btn-outline-primary me-1" 
                                    onClick={() => handleAddToShelf(book.id, shelf.name)}
                                  >
                                    {shelf.name}
                                  </button>
                                ))
                              }
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      
      <AddBookModal
        show={showAddModal}
        handleClose={() => setShowAddModal(false)}
        handleAddBook={handleAddBook}
      />
      
      {selectedBook && (
        <BookNoteModal
          show={showNoteModal}
          handleClose={() => {
            setShowNoteModal(false);
            setSelectedBook(null);
            setCurrentNote(null);
          }}
          bookId={selectedBook.id}
          bookTitle={selectedBook.title}
          existingNote={currentNote}
          handleSaveNote={handleSaveNote}
        />
      )}
    </div>
  );
};

// main app component with routing
function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="d-flex flex-column min-vh-100">
          <Navigation />
          <Container className="flex-grow-1 my-4">
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="*" element={<Home />} />
            </Routes>
          </Container>
          <Footer />
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;