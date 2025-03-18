import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import { Container, Alert } from 'react-bootstrap';
import axios from 'axios';
import 'bootstrap/dist/css/bootstrap.min.css';

// API configuration
const API_URL = 'http://localhost:8000';
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Auth context
const AuthContext = React.createContext(null);

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  // Load user on mount
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

  // Login function
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
        
        // Get user data
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

  // Register function
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

  // Logout function
  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    delete api.defaults.headers.common['Authorization'];
  };

  // Check if user is authenticated
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

// Navigation component
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

// Simple pages
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
  
  if (auth.isAuthenticated()) {
    return <Navigate to="/dashboard" />;
  }
  
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
  
  if (auth.isAuthenticated()) {
    return <Navigate to="/dashboard" />;
  }
  
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    setSuccess('');
    
    // Validate passwords match
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      setIsLoading(false);
      return;
    }
    
    // Validate password length
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

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

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

const Dashboard = () => {
  const auth = React.useContext(AuthContext);
  const [books, setBooks] = useState([]);
  const [showAddModal, setShowAddModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  useEffect(() => {
    // Only fetch if user is authenticated
    if (auth.isAuthenticated()) {
      const fetchBooks = async () => {
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
  
      fetchBooks();
    }
  }, [showAddModal, auth]); // Re-fetch when modal is closed or auth changes
  
  // Redirect if not authenticated
  if (!auth.isAuthenticated()) {
    return <Navigate to="/login" />;
  }
  
  const handleAddBook = async (bookData) => {
    try {
      const response = await api.post('/books/', bookData);
      setBooks(prevBooks => [...prevBooks, response.data]);
      return response.data;
    } catch (error) {
      console.error('Error adding book:', error);
      throw new Error(error.response?.data?.detail || 'Failed to add book');
    }
  };

  const handleAddToShelf = async (bookId, shelfName) => {
    try {
      // Normally we would get the shelf ID from an API call
      // For demo purposes, we'll just show an alert
      alert(`Added book to "${shelfName}" shelf!`);
    } catch (error) {
      console.error('Error adding to shelf:', error);
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
      
      <div className="row mt-4">
        <div className="col-md-4">
          <div className="card">
            <div className="card-header">
              <h4>My Shelves</h4>
            </div>
            <div className="card-body">
              <ul className="list-group">
                <li className="list-group-item">Want to Read</li>
                <li className="list-group-item">Currently Reading</li>
                <li className="list-group-item">Read</li>
              </ul>
            </div>
          </div>
        </div>
        <div className="col-md-8">
          <div className="card">
            <div className="card-header">
              <h4>My Books</h4>
            </div>
            <div className="card-body">
              {loading ? (
                <p>Loading books...</p>
              ) : error ? (
                <Alert variant="danger">{error}</Alert>
              ) : books.length === 0 ? (
                <p>You haven't added any books yet. Click "Add New Book" to get started!</p>
              ) : (
                <div className="list-group">
                  {books.map(book => (
                    <div key={book.id} className="list-group-item list-group-item-action">
                      <div className="d-flex w-100 justify-content-between">
                        <h5 className="mb-1">{book.title}</h5>
                        <small>{book.publication_year}</small>
                      </div>
                      <p className="mb-1">by {book.author}</p>
                      <div className="mt-2">
                        <small className="text-muted me-2">Add to shelf:</small>
                        <button 
                          className="btn btn-sm btn-outline-primary me-1" 
                          onClick={() => handleAddToShelf(book.id, 'Want to Read')}
                        >
                          Want to Read
                        </button>
                        <button 
                          className="btn btn-sm btn-outline-primary me-1" 
                          onClick={() => handleAddToShelf(book.id, 'Currently Reading')}
                        >
                          Currently Reading
                        </button>
                        <button 
                          className="btn btn-sm btn-outline-primary"
                          onClick={() => handleAddToShelf(book.id, 'Read')}
                        >
                          Read
                        </button>
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
    </div>
  );
};

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