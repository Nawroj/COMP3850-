import { Doughnut } from 'react-chartjs-2';
import { Chart, ArcElement, Tooltip, Legend } from 'chart.js';

Chart.register(ArcElement, Tooltip, Legend);

function ThreatTypeChart({ ipCount, domainCount, urlCount, hashCount }) {
  const data = {
    labels: ['IP', 'Domain', 'URL', 'Hash'],
    datasets: [
      {
        label: 'Threat Type Distribution',
        data: [ipCount, domainCount, urlCount, hashCount],
        backgroundColor: [
          'rgba(96, 80, 220, 0.7)',
          'rgba(213, 45, 183, 0.7)',
          'rgba(255, 107, 69, 0.7)',
          'rgba(255, 171, 5, 0.7)',
        ],
        borderColor: [
          'rgba(96, 80, 220, 1)',
          'rgba(213, 45, 183, 1)',
          'rgba(255, 107, 69, 1)',
          'rgba(255, 171, 5, 1)',
        ],
        borderWidth: 1,
      },
    ],
  };

  return (
    <div className="w-full md:w-1/2 mx-auto">
      <h2 className="text-2xl mb-4 text-center">Threat Type Distribution</h2>
      <Doughnut data={data} />
    </div>
  );
}

export default ThreatTypeChart;
