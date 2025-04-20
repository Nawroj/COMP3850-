import { useState, useEffect } from 'react';
import axios from 'axios';

function HashThreats() {
  const [hashData, setHashData] = useState([]);
  const [error, setError] = useState('');
  const [searchHash, setSearchHash] = useState('');
  const [matchedHash, setMatchedHash] = useState(null);
  const [visibleHashCount, setVisibleHashCount] = useState(50); // Initially show 50 hashes
  const [allHashData, setAllHashData] = useState([]); // Store all hash data

  useEffect(() => {
    const fetchHashThreats = async () => {
      try {
        const token = localStorage.getItem('token');
        if (!token) throw new Error('No token found');

        const response = await axios.get('http://localhost:8000/threat_hashes', {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        setAllHashData(response.data); // Store all hash data
        setHashData(response.data.slice(0, visibleHashCount)); // Show only the first 50 initially
      } catch (err) {
        console.error('Failed to fetch hash data:', err.message);
        setError('Failed to load hash threat data.');
      }
    };

    fetchHashThreats();
  }, [visibleHashCount]); // Depend on visibleHashCount to trigger new data load

  const handleSearch = () => {
    const found = hashData.find((item) => item.value === searchHash.trim());
    setMatchedHash(found ? found.value : null);
  };

  const handleSeeMore = () => {
    const newVisibleCount = visibleHashCount + 50;
    setVisibleHashCount(newVisibleCount);
    setHashData(allHashData.slice(0, newVisibleCount)); // Load the next set of 50 hashes
  };

  return (
    <div className="min-h-screen bg-[#0E0B16] flex flex-col">
      {/* Top Bar */}
      <div className="bg-[#161025] p-4 flex items-center justify-between shadow-md">
        <img src="/logo.png" alt="Logo" className="h-10 w-auto" />
        <div />
      </div>

      {/* Main Content */}
      <div className="flex flex-1 justify-center items-center p-6">
        <div className="w-full max-w-4xl">
          <h1 className="text-4xl font-semibold text-white mb-6 text-center">Hash Threats</h1>

          {/* Error Message */}
          {error && <p className="text-red-500 mb-4 text-center">{error}</p>}

          {/* Search Bar */}
          <div className="mb-8 flex items-center justify-center space-x-4">
            <input
              type="text"
              placeholder="Enter hash to search..."
              value={searchHash}
              onChange={(e) => setSearchHash(e.target.value)}
              className="w-full sm:w-1/3 p-3 rounded-md border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <button
              onClick={handleSearch}
              className="bg-blue-600 text-white px-6 py-3 rounded-md hover:bg-blue-700 transition duration-200"
            >
              Search
            </button>
          </div>

          {/* Search Result */}
          {searchHash && (
            <div className="text-center mb-6">
              {matchedHash ? (
                <p className="text-green-500">✅ Hash found: {matchedHash}</p>
              ) : (
                <p className="text-red-500">❌ Hash not found in threat list</p>
              )}
            </div>
          )}

          {/* Hash Threat List */}
          <div className="bg-white rounded-lg shadow-lg p-6 mt-4">
            {hashData.length === 0 ? (
              <p className="text-center text-gray-500">No hash threats found.</p>
            ) : (
              <ul className="space-y-2">
                {hashData.map((item, idx) => (
                  <li key={idx} className="text-lg text-gray-800 hover:text-blue-500 transition duration-200">
                    {item.value}
                  </li>
                ))}
              </ul>
            )}

            {/* See More Button */}
            {hashData.length < allHashData.length && (
              <div className="text-center mt-6">
                <button
                  onClick={handleSeeMore}
                  className="bg-blue-600 text-white px-6 py-3 rounded-md hover:bg-blue-700 transition duration-200"
                >
                  See More
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default HashThreats;
