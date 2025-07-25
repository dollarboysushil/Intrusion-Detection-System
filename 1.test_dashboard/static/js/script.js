document.addEventListener('DOMContentLoaded', () => {
    // Fetch and display metrics
    fetch('/api/metrics')
        .then(response => response.json())
        .then(data => {
            document.querySelector('.total-flows .value').textContent = `${data.total_flows} <small><i class="fas fa-arrow-up red"></i> ${data.ddos_change.toFixed(1)}% from last hour</small>`;
            document.querySelector('.ddos-attacks .value').textContent = `${data.ddos_count} <small><i class="fas fa-arrow-up red"></i> ${data.ddos_change.toFixed(1)}% from last hour</small>`;
            document.querySelector('.port-scans .value').textContent = `${data.port_scan_count} <small><i class="fas fa-arrow-down orange"></i> ${data.port_scan_change.toFixed(1)}% from last hour</small>`;
            document.querySelector('.other-attacks .value').textContent = `${data.other_attack_count} <small><i class="fas fa-arrow-up yellow"></i> ${data.other_attack_change.toFixed(1)}% from last hour</small>`;
        })
        .catch(error => console.error('Error fetching metrics:', error));

    // Fetch and display attack distribution
    fetch('/api/distribution')
        .then(response => response.json())
        .then(data => {
            const ctx = document.getElementById('attack-distribution-chart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: Object.keys(data),
                    datasets: [{
                        label: 'Attack Types',
                        data: Object.values(data),
                        backgroundColor: ['#2ecc71', '#e74c3c', '#f39c12', '#9b59b6'],
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                        }
                    }
                }
            });
        })
        .catch(error => console.error('Error fetching distribution:', error));

    // Fetch and display attack trends
    fetch('/api/trends')
        .then(response => response.json())
        .then(data => {
            const ctx = document.getElementById('attack-trends-chart').getContext('2d');
            const labels = data.map(item => item.hour);
            const ddosData = data.map(item => item.DDoS);
            const portScanData = data.map(item => item.Portscan);
            const otherData = data.map(item => item.Other);

            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'DDoS',
                            data: ddosData,
                            borderColor: '#e74c3c',
                            fill: false,
                        },
                        {
                            label: 'Port Scan',
                            data: portScanData,
                            borderColor: '#f39c12',
                            fill: false,
                        },
                        {
                            label: 'Other Attack',
                            data: otherData,
                            borderColor: '#9b59b6',
                            fill: false,
                        },
                    ]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                        }
                    }
                }
            });
        })
        .catch(error => console.error('Error fetching trends:', error));

    // Fetch and display events per second
    fetch('/api/events_per_second')
        .then(response => response.json())
        .then(data => {
            const ctx = document.getElementById('events-per-second-chart').getContext('2d');
            const labels = data.map(item => item.minute);
            const counts = data.map(item => item.count);

            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Flows/Second',
                        data: counts,
                        borderColor: '#3498db',
                        fill: false,
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                        }
                    }
                }
            });
        })
        .catch(error => console.error('Error fetching events per second:', error));
});