import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

// Create a root element and apply the font family globally
const root = ReactDOM.createRoot(document.getElementById('root'));

root.render(
  <div style={{ fontFamily: 'Poppins, sans-serif' }}>
    <App />
  </div>
);
