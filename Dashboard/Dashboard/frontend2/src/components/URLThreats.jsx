import { useState, useEffect } from 'react';
import axios from 'axios';

function URLThreats({ user }) {
  const [urlData, setUrlData] = useState([]);
  const [error, setError] = useState('');
  const [searchUrl, setSearchUrl] = useState('');
  const [matchedUrl, setMatchedUrl] = useState(null);
  const [visibleUrlCount, setVisibleUrlCount] = useState(50); // Initially show 50 URLs
  const [allUrlData, setAllUrlData] = useState([]); // Store all URL data

  useEffect(() => {
    const fetchUrls = async () => {
      try {
        const response = await axios.get('http://localhost:8000/threat_urls', {
          headers: { Authorization: `Bearer ${user.token}` },
        });
        setAllUrlData(response.data); // Store all URL data
        setUrlData(response.data.slice(0, visibleUrlCount)); // Show only the first 50 initially
      } catch (err) {
        console.error(err.message);
        setError('Failed to load URL threats.');
      }
    };

    fetchUrls();
  }, [user.token, visibleUrlCount]); // Fetch again when visibleUrlCount changes

  const handleSearch = () => {
    const found = urlData.find((item) => item.value === searchUrl.trim());
    setMatchedUrl(found ? found.value : null);
  };

  const handleSeeMore = () => {
    const newVisibleCount = visibleUrlCount + 50;
    setVisibleUrlCount(newVisibleCount);
    setUrlData(allUrlData.slice(0, newVisibleCount)); // Load the next set of 50 URLs
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
          <h1 className="text-4xl font-semibold text-white mb-6 text-center">URL Threats</h1>

          {/* Error Message */}
          {error && <p className="text-red-500 mb-4 text-center">{error}</p>}

          {/* Search Bar */}
          <div className="mb-8 flex items-center justify-center space-x-4">
            <input
              type="text"
              placeholder="Enter URL to search..."
              value={searchUrl}
              onChange={(e) => setSearchUrl(e.target.value)}
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
          {searchUrl && (
            <div className="text-center mb-6">
              {matchedUrl ? (
                <p className="text-green-500">✅ URL found: {matchedUrl}</p>
              ) : (
                <p className="text-red-500">❌ URL not found in threat list</p>
              )}
            </div>
          )}

          {/* URL Threat List */}
          <div className="bg-white rounded-lg shadow-lg p-6 mt-4">
            {urlData.length === 0 ? (
              <p className="text-center text-gray-500">No URL threats found.</p>
            ) : (
              <ul className="space-y-2">
                {urlData.map((item, idx) => (
                  <li key={idx} className="text-lg text-gray-800 hover:text-blue-500 transition duration-200">
                    {item.value}
                  </li>
                ))}
              </ul>
            )}

            {/* See More Button */}
            {urlData.length < allUrlData.length && (
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

export default URLThreats;
