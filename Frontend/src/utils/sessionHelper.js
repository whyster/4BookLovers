import jwtDecode from 'jwt-decode';

// Track user activity
let lastActivityTime = Date.now();

// Update activity time on user interaction
const updateActivityTime = () => {
  lastActivityTime = Date.now();
};

// Check if the session should timeout due to inactivity
export const checkSessionTimeout = () => {
  const token = localStorage.getItem('token');
  
  if (!token) {
    return;
  }
  
  try {
    // Check if token is expired
    const decodedToken = jwtDecode(token);
    const currentTime = Date.now() / 1000;
    
    if (decodedToken.exp < currentTime) {
      // Token expired, log out user
      localStorage.removeItem('token');
      window.location.href = '/login?session_expired=true';
      return;
    }
    
    // Check for inactivity timeout (30 minutes = 1800000 ms)
    const inactiveTime = Date.now() - lastActivityTime;
    if (inactiveTime > 1800000) {
      // Inactive for more than 30 minutes, log out
      localStorage.removeItem('token');
      window.location.href = '/login?session_expired=true';
    }
  } catch (error) {
    console.error('Error checking session timeout:', error);
    localStorage.removeItem('token');
  }
};

// Set up event listeners for user activity
export const setupActivityTracking = () => {
  // List of events to track for user activity
  const events = [
    'mousedown', 'mousemove', 'keypress',
    'scroll', 'touchstart', 'click'
  ];
  
  // Add event listeners
  events.forEach(event => {
    window.addEventListener(event, updateActivityTime);
  });
  
  // Initial activity time
  updateActivityTime();
  
  return () => {
    // Cleanup event listeners
    events.forEach(event => {
      window.removeEventListener(event, updateActivityTime);
    });
  };
};

// Initialize activity tracking
export const initActivityTracking = () => {
  return setupActivityTracking();
};