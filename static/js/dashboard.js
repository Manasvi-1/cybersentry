document.addEventListener('DOMContentLoaded', function() {
    // Load attack data from the server
    const attackDataElement = document.getElementById('attack-data');
    if (attackDataElement) {
        const attackData = JSON.parse(attackDataElement.textContent);
        createAttackChart(attackData);
    }
    
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
});

function createAttackChart(data) {
    const ctx = document.getElementById('attackChart').getContext('2d');
    
    // Extract labels (dates) and counts
    const labels = data.map(item => item.date);
    const counts = data.map(item => item.count);
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Attacks',
                data: counts,
                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 2,
                tension: 0.4,
                pointBackgroundColor: 'rgba(54, 162, 235, 1)',
                pointRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Honeypot Attacks over the Past 7 Days',
                    color: '#fff'
                },
                legend: {
                    display: true,
                    labels: {
                        color: '#fff'
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.7)'
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#fff'
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#fff',
                        precision: 0
                    }
                }
            }
        }
    });
}

// Add event listeners for alerts
document.querySelectorAll('.alert-dismiss').forEach(button => {
    button.addEventListener('click', function(e) {
        const alertId = this.getAttribute('data-alert-id');
        markAlertAsRead(alertId);
    });
});

// Function to mark alert as read via AJAX
function markAlertAsRead(alertId) {
    // In a real implementation, this would use fetch to call the backend
    // For demo purposes, we'll just hide the alert
    const alertElement = document.getElementById(`alert-${alertId}`);
    if (alertElement) {
        alertElement.classList.add('text-muted');
        const badge = alertElement.querySelector('.badge');
        if (badge) {
            badge.classList.remove('bg-danger');
            badge.classList.add('bg-secondary');
            badge.textContent = 'Read';
        }
    }
}
