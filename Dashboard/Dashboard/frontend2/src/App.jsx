import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import AdminPanel from './components/AdminPanel';
import IPThreats from './components/IPThreats';
import DomainThreats from './components/DomainThreats';
import URLThreats from './components/URLThreats';
import HashThreats from './components/HashThreats'; // Import the HashThreats component

function App() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      setUser({ token });
    }
  }, []);

  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login setUser={setUser} />} />
        <Route path="/dashboard" element={user ? <Dashboard user={user} /> : <Navigate to="/login" />} />
        <Route path="/admin" element={user ? <AdminPanel user={user} /> : <Navigate to="/login" />} />
        <Route path="/ip-threats" element={user ? <IPThreats user={user} /> : <Navigate to="/login" />} />
        <Route path="/domain-threats" element={user ? <DomainThreats user={user} /> : <Navigate to="/login" />} />
        <Route path="/url-threats" element={user ? <URLThreats user={user} /> : <Navigate to="/login" />} />
        <Route path="/hash-threats" element={user ? <HashThreats user={user} /> : <Navigate to="/login" />} /> {/* Add HashThreats route */}
        <Route path="*" element={<Navigate to="/login" />} />
      </Routes>
    </Router>
  );
}

export default App;
