import { useEffect, useState } from "react";
import { MapContainer, TileLayer, useMap } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import "leaflet.heat";
import L from "leaflet";

function HeatmapLayer({ points }) {
  const map = useMap();

  useEffect(() => {
    if (!points.length) return;

    const heatLayer = L.heatLayer(points, { radius: 25, blur: 15 }).addTo(map);

    return () => {
      map.removeLayer(heatLayer);
    };
  }, [map, points]);

  return null;
}

function IPHeatmap({ token }) {
  const [locations, setLocations] = useState([]);

  useEffect(() => {
    const fetchLocations = async () => {
      try {
        const ipRes = await fetch("http://localhost:8000/threat_ips", {
          headers: { Authorization: `Bearer ${token}` },
        });
        const ipData = await ipRes.json();
        const ips = ipData.map((item) => item.value).slice(0, 30); // limit

        const locs = await Promise.all(
          ips.map(async (ip) => {
            const res = await fetch(`http://localhost:8000/geocode/${ip}`, {
              headers: { Authorization: `Bearer ${token}` },
            });
            const data = await res.json();
            if (data.lat && data.lon) return [data.lat, data.lon];
            return null;
          })
        );

        setLocations(locs.filter(Boolean));
      } catch (err) {
        console.error("Error fetching heatmap data:", err);
      }
    };

    fetchLocations();
  }, [token]);

  return (
    <div className="bg-white mt-8 p-4 rounded shadow">
      <h2 className="text-xl font-semibold mb-4">IP Geolocation Heatmap</h2>
      <MapContainer
        center={[20, 0]}
        zoom={2}
        scrollWheelZoom={false}
        style={{ height: "500px", width: "100%" }}
      >
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution="© OpenStreetMap contributors"
        />
        <HeatmapLayer points={locations} />
      </MapContainer>
    </div>
  );
}

export default IPHeatmap;
