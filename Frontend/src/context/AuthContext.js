import React, { createContext, useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import jwtDecode from 'jwt-decode';
import api from '../utils/api';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  // Load user on mount
  useEffect(() => {
    const loadUser = async () => {
      if (token) {
        try {
          // Check if token is expired
          const decodedToken = jwtDecode(token);
          const currentTime = Date.now() / 1000;
          
          if (decodedToken.exp < currentTime) {
            // Token expired, log out user
            logout();
            return;
          }
          
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
      
      const { data } = await api.post('/token', formData);
      
      if (data.access_token) {
        localStorage.setItem('token', data.access_token);
        setToken(data.access_token);
        api.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`;
        
        // Get user data
        const { data: userData } = await api.get('/users/me');
        setUser(userData);
        
        return true;
      }
    } catch (error) {
      console.error('Login error:', error);
      if (error.response && error.response.data) {
        toast.error(error.response.data.detail || 'Login failed');
      } else {
        toast.error('Login failed. Please check your credentials.');
      }
      return false;
    }
  };

  // Register function
  const register = async (userData) => {
    try {
      const { data } = await api.post('/users/', userData);
      toast.success('Registration successful! Please log in.');
      return true;
    } catch (error) {
      console.error('Register error:', error);
      if (error.response && error.response.data) {
        toast.error(error.response.data.detail || 'Registration failed');
      } else {
        toast.error('Registration failed. Please try again.');
      }
      return false;
    }
  };

  // Logout function
  const logout = async () => {
    try {
      if (token) {
        await api.post('/logout');
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('token');
      setToken(null);
      setUser(null);
      delete api.defaults.headers.common['Authorization'];
      toast.info('Logged out successfully');
    }
  };

  // Check if user is authenticated
  const isAuthenticated = () => {
    return !!token && !!user;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
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