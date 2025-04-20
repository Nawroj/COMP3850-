import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const AdminPanel = ({ user }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('user');
  const [message, setMessage] = useState('');
  const navigate = useNavigate();

  const axiosInstance = axios.create({
    headers: { Authorization: `Bearer ${user.token}` }
  });

  const handleAddUser = async (e) => {
    e.preventDefault();
    try {
      await axiosInstance.post('http://localhost:8000/users', {
        username,
        password,
        role
      });
      setMessage('User created successfully');
      setUsername('');
      setPassword('');
      setRole('user');
    } catch (err) {
      setMessage('Error creating user');
    }
  };

  const handleRefresh = async () => {
    try {
      await axiosInstance.post('http://localhost:8000/refresh_feeds');
      setMessage('Feed refresh triggered');
    } catch (err) {
      setMessage('Error triggering refresh');
    }
  };

  return (
    <div className="flex">
      <div className="w-64 bg-gray-800 text-white h-screen p-4">
        <h2 className="text-xl mb-4">Admin Panel</h2>
        <nav>
          <button
            onClick={() => navigate('/dashboard')}
            className="block w-full text-left py-2 px-4 hover:bg-gray-700"
          >
            Dashboard
          </button>
          <button
            onClick={() => navigate('/admin')}
            className="block w-full text-left py-2 px-4 hover:bg-gray-700"
          >
            Admin
          </button>
          <button
            onClick={() => {
              localStorage.removeItem('token');
              navigate('/login');
            }}
            className="block w-full text-left py-2 px-4 hover:bg-gray-700"
          >
            Logout
          </button>
        </nav>
      </div>
      <div className="flex-1 p-8 bg-gray-100">
        <h1 className="text-3xl mb-8">Admin Panel</h1>
        <div className="bg-white p-4 rounded shadow mb-8">
          <h2 className="text-xl mb-4">Add New User</h2>
          {message && <p className="mb-4 text-green-500">{message}</p>}
          <div>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="p-2 border rounded mr-2"
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="p-2 border rounded mr-2"
            />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="p-2 border rounded mr-2"
            >
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
            <button
              onClick={handleAddUser}
              className="bg-blue-500 text-white p-2 rounded"
            >
              Add User
            </button>
          </div>
        </div>
        <div className="bg-white p-4 rounded shadow">
          <h2 className="text-xl mb-4">Refresh Feeds</h2>
          <button
            onClick={handleRefresh}
            className="bg-blue-500 text-white p-2 rounded"
          >
            Refresh Feeds
          </button>
        </div>
      </div>
    </div>
  );
};

export default AdminPanel;