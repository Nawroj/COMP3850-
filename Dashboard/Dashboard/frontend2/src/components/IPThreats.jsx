import { useState, useEffect } from 'react';
import axios from 'axios';

function IPThreats() {
  const [ipData, setIpData] = useState([]);
  const [error, setError] = useState('');
  const [searchIP, setSearchIP] = useState('');
  const [matchedIP, setMatchedIP] = useState(null);
  const [visibleIpCount, setVisibleIpCount] = useState(50); // Initially show 50 IPs
  const [allIpData, setAllIpData] = useState([]); // Store all IP data

  useEffect(() => {
    const fetchIps = async () => {
      try {
        const response = await axios.get('http://localhost:8000/threat_ips', {
          headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }, // Fixed to use token from localStorage
        });
        setAllIpData(response.data); // Store all IP data
        setIpData(response.data.slice(0, visibleIpCount)); // Show only the first 50 initially
      } catch (err) {
        console.error(err.message);
        setError('Failed to load IP threats.');
      }
    };

    fetchIps();
  }, [visibleIpCount]); // Only re-run when visibleIpCount changes

  const handleSearch = () => {
    const found = ipData.find((item) => item.value === searchIP.trim());
    setMatchedIP(found ? found.value : null);
  };

  const handleSeeMore = () => {
    const newVisibleCount = visibleIpCount + 50;
    setVisibleIpCount(newVisibleCount);
    setIpData(allIpData.slice(0, newVisibleCount)); // Load the next set of 50 IPs
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
          <h1 className="text-4xl font-semibold text-white mb-6 text-center">IP Threats</h1>

          {/* Error Message */}
          {error && <p className="text-red-500 mb-4 text-center">{error}</p>}

          {/* Search Bar */}
          <div className="mb-8 flex items-center justify-center space-x-4">
            <input
              type="text"
              placeholder="Enter IP to search..."
              value={searchIP}
              onChange={(e) => setSearchIP(e.target.value)}
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
          {searchIP && (
            <div className="text-center mb-6">
              {matchedIP ? (
                <p className="text-green-500">✅ IP found: {matchedIP}</p>
              ) : (
                <p className="text-red-500">❌ IP not found in threat list</p>
              )}
            </div>
          )}

          {/* IP Threat List */}
          <div className="bg-white rounded-lg shadow-lg p-6 mt-4">
            {ipData.length === 0 ? (
              <p className="text-center text-gray-500">No IP threats found.</p>
            ) : (
              <ul className="space-y-2">
                {ipData.map((item, idx) => (
                  <li key={idx} className="text-lg text-gray-800 hover:text-blue-500 transition duration-200">
                    {item.value}
                  </li>
                ))}
              </ul>
            )}

            {/* See More Button */}
            {ipData.length < allIpData.length && (
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

export default IPThreats;
