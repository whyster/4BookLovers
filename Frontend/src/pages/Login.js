import React, { useState, useContext, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Form, Button, Card, Alert } from 'react-bootstrap';
import { AuthContext } from '../context/AuthContext';
import { Formik } from 'formik';
import * as Yup from 'yup';

const Login = () => {
  const { login, isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();
  const location = useLocation();
  const [loginError, setLoginError] = useState('');
  const [loginAttempts, setLoginAttempts] = useState(0);

  // Check if user is already logged in
  useEffect(() => {
    if (isAuthenticated()) {
      navigate('/');
    }
  }, [isAuthenticated, navigate]);

  // Check for session expired parameter
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    if (params.get('session_expired') === 'true') {
      setLoginError('Your session has expired. Please log in again.');
    }
  }, [location]);

  // Login validation schema
  const validationSchema = Yup.object({
    username: Yup.string().required('Username is required'),
    password: Yup.string().required('Password is required'),
  });

  // Handle login submission
  const handleSubmit = async (values, { setSubmitting }) => {
    setLoginError('');
    
    // Check for too many login attempts
    if (loginAttempts >= 5) {
      setLoginError('Too many failed login attempts. Please try again later.');
      setSubmitting(false);
      return;
    }
    
    try {
      const result = await login(values.username, values.password);
      
      if (result) {
        navigate('/');
      } else {
        setLoginAttempts(prev => prev + 1);
        setLoginError('Invalid username or password');
        
        // If 5 attempts reached, show lockout message
        if (loginAttempts + 1 >= 5) {
          setLoginError('Account locked due to too many failed attempts. Please try again after 24 hours.');
        }
      }
    } catch (error) {
      setLoginError('Login failed. Please try again.');
      setLoginAttempts(prev => prev + 1);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="d-flex justify-content-center">
      <Card className="login-card" style={{ width: '400px' }}>
        <Card.Body>
          <Card.Title className="text-center mb-4">Login to 4BookLovers</Card.Title>
          
          {loginError && (
            <Alert variant="danger">{loginError}</Alert>
          )}
          
          <Formik
            initialValues={{ username: '', password: '' }}
            validationSchema={validationSchema}
            onSubmit={handleSubmit}
          >
            {({
              values,
              errors,
              touched,
              handleChange,
              handleBlur,
              handleSubmit,
              isSubmitting,
            }) => (
              <Form onSubmit={handleSubmit}>
                <Form.Group className="mb-3">
                  <Form.Label>Username</Form.Label>
                  <Form.Control
                    type="text"
                    name="username"
                    value={values.username}
                    onChange={handleChange}
                    onBlur={handleBlur}
                    isInvalid={touched.username && errors.username}
                  />
                  <Form.Control.Feedback type="invalid">
                    {errors.username}
                  </Form.Control.Feedback>
                </Form.Group>

                <Form.Group className="mb-3">
                  <Form.Label>Password</Form.Label>
                  <Form.Control
                    type="password"
                    name="password"
                    value={values.password}
                    onChange={handleChange}
                    onBlur={handleBlur}
                    isInvalid={touched.password && errors.password}
                  />
                  <Form.Control.Feedback type="invalid">
                    {errors.password}
                  </Form.Control.Feedback>
                </Form.Group>

                <Button
                  variant="primary"
                  type="submit"
                  className="w-100 mt-3"
                  disabled={isSubmitting || loginAttempts >= 5}
                >
                  {isSubmitting ? 'Logging in...' : 'Login'}
                </Button>
              </Form>
            )}
          </Formik>
          
          <div className="text-center mt-3">
            <p>
              Don't have an account?{' '}
              <a href="/register" className="text-decoration-none">
                Register
              </a>
            </p>
          </div>
        </Card.Body>
      </Card>
    </div>
  );
};

export default Login;