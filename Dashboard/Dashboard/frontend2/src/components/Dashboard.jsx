import { useState, useEffect } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import ThreatTypeChart from './ThreatTypeChart';
import SourceCountsChart from './SourceCountsChart'; // Import the new chart component

function Dashboard({ user }) {
  const [ipCount, setIpCount] = useState(null);
  const [domainCount, setDomainCount] = useState(null);
  const [urlCount, setUrlCount] = useState(null);
  const [hashCount, setHashCount] = useState(null);
  const [sourceCounts, setSourceCounts] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchThreatData = async () => {
      try {
        const token = localStorage.getItem('token');
        if (!token) {
          throw new Error('No token found');
        }

        const axiosInstance = axios.create({
          headers: { Authorization: `Bearer ${token}` },
        });

        const [
          ip,
          domain,
          url,
          hash,
          sources,
        ] = await Promise.all([
          axiosInstance.get('http://localhost:8000/threat_ip_count'),
          axiosInstance.get('http://localhost:8000/threat_domain_count'),
          axiosInstance.get('http://localhost:8000/threat_url_count'),
          axiosInstance.get('http://localhost:8000/threat_hash_count'),
          axiosInstance.get('http://localhost:8000/source_count'), // Fetch source counts
        ]);

        setIpCount(ip.data.ip_count.toString());
        setDomainCount(domain.data.domain_count.toString());
        setUrlCount(url.data.url_count.toString());
        setHashCount(hash.data.hash_count.toString());
        setSourceCounts(sources.data); // Set the source counts data

      } catch (err) {
        console.error('Error fetching threat data:', err.message);
        setError('Failed to load threat data');
      }
    };

    fetchThreatData();
  }, [user.token]);

  return (
    <div className="min-h-screen bg-[#0E0B16]">
      {/* Top Bar */}
      <div className="bg-[#161025] p-4 flex items-center justify-between shadow-md">
        <img src="/logo.png" alt="Logo" className="h-10 w-auto" />
        <div />
      </div>

      {/* Main Dashboard Wrapper with Elevation */}
      <div className="max-w-7xl mx-auto mt-10 p-6 bg-[#161025] shadow-lg rounded-xl">
        <h2 className="text-3xl text-white font-semibold mb-4">Dashboard</h2>
        {error && <p className="text-red-500 mb-4">{error}</p>}

        {/* Wrapped Counts Section */}
        <div className="mb-10 bg-[#0E0B16] p-6 rounded shadow">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Link to="/ip-threats">
              <div className="bg-gray-100 p-4 rounded shadow cursor-pointer hover:bg-gray-200">
                <h2 className="text-xl mb-2">IP Threats</h2>
                <p className="text-lg">{ipCount !== null ? `${ipCount} detected` : 'Loading...'}</p>
              </div>
            </Link>

            <Link to="/domain-threats">
              <div className="bg-gray-100 p-4 rounded shadow cursor-pointer hover:bg-gray-200">
                <h2 className="text-xl mb-2">Domain Threats</h2>
                <p className="text-lg">{domainCount !== null ? `${domainCount} detected` : 'Loading...'}</p>
              </div>
            </Link>

            <Link to="/url-threats">
              <div className="bg-gray-100 p-4 rounded shadow cursor-pointer hover:bg-gray-200">
                <h2 className="text-xl mb-2">URL Threats</h2>
                <p className="text-lg">{urlCount !== null ? `${urlCount} detected` : 'Loading...'}</p>
              </div>
            </Link>

            <Link to="/hash-threats">
              <div className="bg-gray-100 p-4 rounded shadow cursor-pointer hover:bg-gray-200">
                <h2 className="text-xl mb-2">Hash Threats</h2>
                <p className="text-lg">{hashCount !== null ? `${hashCount} detected` : 'Loading...'}</p>
              </div>
            </Link>
          </div>
        </div>

        {/* Chart Section */}
        <div className="flex flex-wrap gap-6 bg-[#0E0B16] p-6 rounded shadow">
          {/* Threat Type Chart */}
          {(ipCount && domainCount && urlCount && hashCount) && (
            <div className="bg-gray-100 p-6 rounded shadow w-full md:w-2/3 lg:w-[48%]">
              <ThreatTypeChart
                ipCount={parseInt(ipCount)}
                domainCount={parseInt(domainCount)}
                urlCount={parseInt(urlCount)}
                hashCount={parseInt(hashCount)}
              />
            </div>
          )}

          {/* Source Counts Chart */}
          {sourceCounts.length > 0 && (
            <div className="bg-gray-100 p-6 rounded shadow w-full md:w-2/3 lg:w-[48%]">
              <SourceCountsChart data={sourceCounts} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;