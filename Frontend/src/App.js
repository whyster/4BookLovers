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
        <Link className="navbar-brand d-flex align-items-center" to="/">
          <i className="fas fa-book-open me-2"></i> 4BookLovers
        </Link>
        <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarNav">
          <ul className="navbar-nav ms-auto">
            {auth.isAuthenticated() ? (
              <>
                <li className="nav-item mx-1">
                  <Link className="nav-link" to="/dashboard">
                    <i className="fas fa-book me-1"></i> My Books
                  </Link>
                </li>
                <li className="nav-item dropdown mx-1">
                  <a className="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                    <i className="fas fa-user-circle me-1"></i> {auth.user?.username}
                  </a>
                  <ul className="dropdown-menu dropdown-menu-end" aria-labelledby="navbarDropdown">
                    <li>
                      <Link className="dropdown-item" to="/dashboard">
                        <i className="fas fa-tachometer-alt me-2"></i> Dashboard
                      </Link>
                    </li>
                    <li><hr className="dropdown-divider" /></li>
                    <li>
                      <a className="dropdown-item" href="#" onClick={auth.logout}>
                        <i className="fas fa-sign-out-alt me-2"></i> Logout
                      </a>
                    </li>
                  </ul>
                </li>
              </>
            ) : (
              <>
                <li className="nav-item mx-1">
                  <Link className="nav-link" to="/login">
                    <i className="fas fa-sign-in-alt me-1"></i> Login
                  </Link>
                </li>
                <li className="nav-item mx-1">
                  <Link className="nav-link btn btn-primary text-white px-3" to="/register">
                    <i className="fas fa-user-plus me-1"></i> Register
                  </Link>
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
  <footer className="bg-dark text-light py-4 mt-auto">
    <div className="container">
      <div className="row">
        <div className="col-md-4 mb-3 mb-md-0">
          <h5 className="mb-3">4BookLovers</h5>
          <p className="mb-0 text-light-50">A platform for book enthusiasts to discover, track, and share their reading journey.</p>
        </div>
        <div className="col-md-4 mb-3 mb-md-0">
          <h5 className="mb-3">Quick Links</h5>
          <ul className="list-unstyled">
            <li><Link to="/" className="text-decoration-none text-light-50">Home</Link></li>
            <li><Link to="/login" className="text-decoration-none text-light-50">Login</Link></li>
            <li><Link to="/register" className="text-decoration-none text-light-50">Register</Link></li>
          </ul>
        </div>
        <div className="col-md-4">
          <h5 className="mb-3">Connect</h5>
          <div className="d-flex gap-3">
            <a href="#" className="text-light"><i className="fab fa-facebook-f fa-lg"></i></a>
            <a href="#" className="text-light"><i className="fab fa-twitter fa-lg"></i></a>
            <a href="#" className="text-light"><i className="fab fa-instagram fa-lg"></i></a>
            <a href="#" className="text-light"><i className="fab fa-goodreads-g fa-lg"></i></a>
          </div>
        </div>
      </div>
      <hr className="my-3 bg-light" />
      <div className="text-center">
        <p className="mb-0">© 2025 4BookLovers - All rights reserved</p>
      </div>
    </div>
  </footer>
);

// home page with improved UI for unauthenticated users
const Home = () => (
  <div>
    <div className="home-hero text-center mb-5 p-5 rounded">
      <h1 className="display-4 fw-bold text-white">Welcome to 4BookLovers</h1>
      <p className="lead text-white mb-4">Discover, track, and share your reading journey</p>
      <div className="d-grid gap-2 d-sm-flex justify-content-sm-center">
        <Link to="/login" className="btn btn-light btn-lg px-4 gap-3">
          <i className="fas fa-sign-in-alt me-2"></i> Log In
        </Link>
        <Link to="/register" className="btn btn-outline-light btn-lg px-4">
          <i className="fas fa-user-plus me-2"></i> Sign Up
        </Link>
      </div>
    </div>
    
    <div className="container">
      <div className="row mb-5">
        <div className="col-md-4 mb-4">
          <div className="card h-100 text-center p-4">
            <div className="card-body">
              <div className="mb-4">
                <i className="fas fa-book fa-3x text-primary-custom"></i>
              </div>
              <h3 className="card-title h4 mb-3">Track Your Reading</h3>
              <p className="card-text">Keep track of books you've read, are currently reading, or want to read in the future.</p>
            </div>
          </div>
        </div>
        <div className="col-md-4 mb-4">
          <div className="card h-100 text-center p-4">
            <div className="card-body">
              <div className="mb-4">
                <i className="fas fa-bookmark fa-3x text-primary-custom"></i>
              </div>
              <h3 className="card-title h4 mb-3">Create Custom Shelves</h3>
              <p className="card-text">Organize your books into custom shelves based on genres, themes, or any category you can imagine.</p>
            </div>
          </div>
        </div>
        <div className="col-md-4 mb-4">
          <div className="card h-100 text-center p-4">
            <div className="card-body">
              <div className="mb-4">
                <i className="fas fa-pencil-alt fa-3x text-primary-custom"></i>
              </div>
              <h3 className="card-title h4 mb-3">Take Personal Notes</h3>
              <p className="card-text">Add private or public notes to any book to remember your thoughts and insights.</p>
            </div>
          </div>
        </div>
      </div>
      
      <h2 className="text-center mb-4">Popular Books</h2>
      <div className="row justify-content-center">
        {[
          { 
            title: 'The Great Gatsby', 
            author: 'F. Scott Fitzgerald', 
            image: 'https://m.media-amazon.com/images/I/71FTb9X6wsL._AC_UF1000,1000_QL80_.jpg',
            year: 1925
          },
          { 
            title: 'To Kill a Mockingbird', 
            author: 'Harper Lee', 
            image: 'https://m.media-amazon.com/images/I/71FxgtFKcQL._AC_UF1000,1000_QL80_.jpg',
            year: 1960
          },
          { 
            title: 'Pride and Prejudice', 
            author: 'Jane Austen', 
            image: 'https://m.media-amazon.com/images/I/71Q1tPupKjL._AC_UF1000,1000_QL80_.jpg',
            year: 1813
          },
          { 
            title: '1984', 
            author: 'George Orwell', 
            image: 'https://m.media-amazon.com/images/I/71kxa1-0mfL._AC_UF1000,1000_QL80_.jpg',
            year: 1949
          }
        ].map(book => (
          <div key={book.title} className="col-md-3 mb-4">
            <div className="card h-100">
              <div className="card-img-top bg-light-custom d-flex justify-content-center align-items-center" style={{ height: '200px', overflow: 'hidden' }}>
                <img 
                  src={book.image} 
                  alt={book.title} 
                  style={{ maxHeight: '100%', maxWidth: '100%', objectFit: 'contain' }}
                />
              </div>
              <div className="card-body">
                <h5 className="card-title">{book.title}</h5>
                <p className="card-text text-muted mb-1">{book.author}</p>
                <small className="text-muted">{book.year}</small>
              </div>
            </div>
          </div>
        ))}
      </div>
      
      <div className="text-center my-5 py-3">
        <h3>Join thousands of book lovers today!</h3>
        <p className="lead">Create your account to start your reading journey</p>
        <Link to="/register" className="btn btn-primary btn-lg px-4">
          Get Started <i className="fas fa-arrow-right ms-2"></i>
        </Link>
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

// modal component for adding a new bookshelf
const AddShelfModal = ({ show, handleClose, handleAddShelf }) => {
  const [formData, setFormData] = useState({
    name: '',
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
      await handleAddShelf(formData);
      handleClose();
    } catch (error) {
      setError(error.response?.data?.detail || error.message || 'Failed to add bookshelf');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={`modal ${show ? 'd-block' : 'd-none'}`} tabIndex="-1" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
      <div className="modal-dialog modal-dialog-centered">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">Create New Bookshelf</h5>
            <button type="button" className="btn-close" onClick={handleClose}></button>
          </div>
          <div className="modal-body">
            {error && <Alert variant="danger">{error}</Alert>}
            <form onSubmit={handleSubmit}>
              <div className="mb-3">
                <label htmlFor="name" className="form-label">Shelf Name *</label>
                <input 
                  type="text" 
                  className="form-control" 
                  id="name" 
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  placeholder="e.g., Fantasy Books, Summer Reading, etc."
                  required
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
                  placeholder="Optional description of this bookshelf"
                ></textarea>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={handleClose}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={isLoading}>
                  {isLoading ? 'Creating...' : 'Create Bookshelf'}
                </button>
              </div>
            </form>
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
  const [showAddBookModal, setShowAddBookModal] = useState(false);
  const [showAddShelfModal, setShowAddShelfModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [searchBy, setSearchBy] = useState('all');
  const [sortOrder, setSortOrder] = useState('recent');
  const [showAdvancedSearch, setShowAdvancedSearch] = useState(false);
  const [yearFrom, setYearFrom] = useState('');
  const [yearTo, setYearTo] = useState('');
  const [language, setLanguage] = useState('');
  const [searchShelves, setSearchShelves] = useState([]);
  
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
  }, [auth, showAddShelfModal]); // Re-fetch when add shelf modal closes

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
  
  // Function to build search params from all search state
  const buildSearchParams = () => {
    const params = new URLSearchParams();
    
    if (searchQuery.trim()) {
      params.append('query', searchQuery.trim());
    }
    
    params.append('search_by', searchBy);
    
    // Add sort parameter
    const [sortField, sortDirection] = sortOrder.split('_');
    if (sortField && sortField !== 'recent') {
      params.append('sort_field', sortField);
      params.append('sort_direction', sortDirection || 'asc');
    }
    
    // Add advanced search parameters if they exist
    if (yearFrom) params.append('year_from', yearFrom);
    if (yearTo) params.append('year_to', yearTo);
    if (language) params.append('language', language);
    
    // Add shelf filtering
    if (searchShelves.length > 0) {
      searchShelves.forEach(shelfId => {
        params.append('shelf_ids', shelfId);
      });
    }
    
    return params;
  };
  
  // Toggle a shelf in the search shelves array
  const toggleSearchShelf = (shelfId) => {
    setSearchShelves(prevShelves => {
      if (prevShelves.includes(shelfId)) {
        return prevShelves.filter(id => id !== shelfId);
      } else {
        return [...prevShelves, shelfId];
      }
    });
  };
  
  // function to search books with advanced parameters
  const searchBooks = async () => {
    setLoading(true);
    setIsSearching(true);
    try {
      const params = buildSearchParams();
      const response = await api.get(`/books/?${params.toString()}`);
      
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
    if (searchQuery.trim() || yearFrom || yearTo || language || searchShelves.length > 0) {
      searchBooks();
    } else {
      setIsSearching(false);
      if (selectedShelf) {
        fetchBooksByShelf(selectedShelf);
      } else {
        fetchAllBooks();
      }
    }
  };
  
  // Clear all search parameters
  const handleClearSearch = () => {
    setSearchQuery('');
    setSearchBy('all');
    setSortOrder('recent');
    setYearFrom('');
    setYearTo('');
    setLanguage('');
    setSearchShelves([]);
    setShowAdvancedSearch(false);
    setIsSearching(false);
    
    if (selectedShelf) {
      fetchBooksByShelf(selectedShelf);
    } else {
      fetchAllBooks();
    }
  };
  
  // fetch books based on the selected shelf or all books
  useEffect(() => {
    if (auth.isAuthenticated()) {
      if (isSearching) {
        searchBooks();
      } else if (selectedShelf) {
        fetchBooksByShelf(selectedShelf);
      } else {
        fetchAllBooks();
      }
    }
  }, [selectedShelf, showAddBookModal, auth, isSearching]); // re-fetch when shelf changes, modal is closed, auth changes, or search status changes
  
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

  // function to create a new bookshelf
  const handleAddShelf = async (shelfData) => {
    try {
      const response = await api.post('/shelves/', shelfData);
      setShelves(prevShelves => [...prevShelves, response.data]);
      return response.data;
    } catch (error) {
      console.error('Error creating bookshelf:', error);
      throw error;
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
  
  // This function has been replaced by the enhanced handleClearSearch above
  
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
        <div>
          <button 
            className="btn btn-primary me-2" 
            onClick={() => setShowAddShelfModal(true)}
          >
            Create New Bookshelf
          </button>
          <button 
            className="btn btn-primary" 
            onClick={() => setShowAddBookModal(true)}
          >
            Add New Book
          </button>
        </div>
      </div>
      
      <div className="mb-4">
        <div className="card">
          <div className="card-body">
            <form onSubmit={handleSearch}>
              <div className="row g-3">
                <div className="col-md-6">
                  <div className="input-group">
                    <span className="input-group-text bg-white border-end-0">
                      <i className="fas fa-search text-primary-custom"></i>
                    </span>
                    <input
                      type="text"
                      className="form-control border-start-0"
                      placeholder="Search books..."
                      value={searchQuery}
                      onChange={handleSearchChange}
                      aria-label="Search books"
                    />
                  </div>
                </div>
                <div className="col-md-2">
                  <select 
                    className="form-select" 
                    value={searchBy} 
                    onChange={(e) => setSearchBy(e.target.value)}
                    aria-label="Search field"
                  >
                    <option value="all">All Fields</option>
                    <option value="title">Title</option>
                    <option value="author">Author</option>
                    <option value="isbn">ISBN</option>
                  </select>
                </div>
                <div className="col-md-2">
                  <select 
                    className="form-select" 
                    value={sortOrder} 
                    onChange={(e) => setSortOrder(e.target.value)}
                    aria-label="Sort order"
                  >
                    <option value="recent">Most Recent</option>
                    <option value="title_asc">Title (A-Z)</option>
                    <option value="title_desc">Title (Z-A)</option>
                    <option value="author_asc">Author (A-Z)</option>
                    <option value="author_desc">Author (Z-A)</option>
                    <option value="year_asc">Year (Oldest)</option>
                    <option value="year_desc">Year (Newest)</option>
                  </select>
                </div>
                <div className="col-md-2 d-flex">
                  <button type="submit" className="btn btn-primary me-2 flex-grow-1">
                    <i className="fas fa-search me-2"></i> Search
                  </button>
                  {isSearching && (
                    <button 
                      type="button" 
                      className="btn btn-outline-secondary"
                      onClick={handleClearSearch}
                    >
                      <i className="fas fa-times"></i>
                    </button>
                  )}
                </div>
              </div>
              
              {/* Advanced search toggle */}
              <div className="mt-2">
                <button 
                  type="button" 
                  className="btn btn-link text-primary-custom p-0" 
                  onClick={() => setShowAdvancedSearch(!showAdvancedSearch)}
                >
                  <i className={`fas fa-chevron-${showAdvancedSearch ? 'up' : 'down'} me-1`}></i>
                  {showAdvancedSearch ? 'Hide' : 'Show'} Advanced Search
                </button>
              </div>
              
              {/* Advanced search options */}
              {showAdvancedSearch && (
                <div className="row mt-3 g-3">
                  <div className="col-md-3">
                    <label className="form-label">Publication Year</label>
                    <div className="d-flex align-items-center">
                      <input
                        type="number"
                        className="form-control"
                        placeholder="From"
                        value={yearFrom}
                        onChange={(e) => setYearFrom(e.target.value)}
                        min="0"
                        max="9999"
                      />
                      <span className="mx-2">-</span>
                      <input
                        type="number"
                        className="form-control"
                        placeholder="To"
                        value={yearTo}
                        onChange={(e) => setYearTo(e.target.value)}
                        min="0"
                        max="9999"
                      />
                    </div>
                  </div>
                  <div className="col-md-3">
                    <label className="form-label">Language</label>
                    <select 
                      className="form-select" 
                      value={language} 
                      onChange={(e) => setLanguage(e.target.value)}
                    >
                      <option value="">Any Language</option>
                      <option value="en">English</option>
                      <option value="es">Spanish</option>
                      <option value="fr">French</option>
                      <option value="de">German</option>
                      <option value="it">Italian</option>
                      <option value="ja">Japanese</option>
                      <option value="zh">Chinese</option>
                    </select>
                  </div>
                  <div className="col-md-6">
                    <label className="form-label">Shelves</label>
                    <div className="d-flex flex-wrap gap-2">
                      {shelves.map(shelf => (
                        <div className="form-check" key={`search-${shelf.id}`}>
                          <input
                            className="form-check-input"
                            type="checkbox"
                            id={`search-shelf-${shelf.id}`}
                            checked={searchShelves.includes(shelf.id)}
                            onChange={() => toggleSearchShelf(shelf.id)}
                          />
                          <label className="form-check-label" htmlFor={`search-shelf-${shelf.id}`}>
                            {shelf.name}
                          </label>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </form>
          </div>
        </div>
      </div>
      
      <div className="row mt-4">
        <div className="col-md-4">
          <div className="card">
            <div className="card-header d-flex justify-content-between align-items-center">
              <h4 className="mb-0">My Shelves</h4>
              <button 
                className="btn btn-sm btn-outline-primary" 
                onClick={() => setShowAddShelfModal(true)}
                title="Create a new bookshelf"
              >
                + Add Shelf
              </button>
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
                    {shelf.is_default && <small className="badge bg-secondary ms-2">Default</small>}
                  </li>
                ))}
              </ul>
              {shelves.length === 0 && (
                <div className="alert alert-info mt-3">
                  You have no bookshelves yet. Click "Create New Bookshelf" to get started.
                </div>
              )}
            </div>
          </div>
        </div>
        <div className="col-md-8">
          <div className="card">
            <div className="card-header">
              <div className="d-flex justify-content-between align-items-center">
                <h4 className="mb-0">
                  {isSearching 
                    ? (
                      <span>
                        Search results 
                        {searchQuery && <span> for "<strong>{searchQuery}</strong>"</span>}
                        {(yearFrom || yearTo) && (
                          <span> from {yearFrom || 'earliest'} to {yearTo || 'latest'}</span>
                        )}
                        {language && <span> in {language.toUpperCase()}</span>}
                      </span>
                    ) 
                    : selectedShelf 
                      ? `Books in "${selectedShelf.name}"` 
                      : 'All Books'
                  }
                </h4>
                {isSearching && books.length > 0 && (
                  <small className="text-muted">{books.length} {books.length === 1 ? 'result' : 'results'}</small>
                )}
              </div>
              
              {isSearching && searchShelves.length > 0 && (
                <div className="mt-2">
                  <small className="text-muted">
                    Filtered by shelves: {shelves
                      .filter(shelf => searchShelves.includes(shelf.id))
                      .map(shelf => shelf.name)
                      .join(', ')
                    }
                  </small>
                </div>
              )}
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
      
      {/* Modals */}
      <AddBookModal
        show={showAddBookModal}
        handleClose={() => setShowAddBookModal(false)}
        handleAddBook={handleAddBook}
      />
      
      <AddShelfModal
        show={showAddShelfModal}
        handleClose={() => setShowAddShelfModal(false)}
        handleAddShelf={handleAddShelf}
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