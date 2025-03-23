document.addEventListener('DOMContentLoaded', function() {
    // Toggle attack details
    const toggleButtons = document.querySelectorAll('.toggle-attack-details');
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const targetElement = document.getElementById(targetId);
            
            if (targetElement.classList.contains('d-none')) {
                targetElement.classList.remove('d-none');
                this.innerHTML = '<i class="bi bi-chevron-up"></i> Hide Details';
            } else {
                targetElement.classList.add('d-none');
                this.innerHTML = '<i class="bi bi-chevron-down"></i> Show Details';
            }
        });
    });
    
    // Confirm honeypot deletion
    const deleteButtons = document.querySelectorAll('.delete-honeypot');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to delete this honeypot? All associated data will be lost.')) {
                e.preventDefault();
            }
        });
    });
    
    // Confirm attack simulation
    const simulateButtons = document.querySelectorAll('.simulate-attack');
    simulateButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('This will simulate an attack on your honeypot. Continue?')) {
                e.preventDefault();
            }
        });
    });
    
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    
    // Create attack type distribution chart if element exists
    const attackTypeChartElement = document.getElementById('attackTypeChart');
    if (attackTypeChartElement) {
        createAttackTypeChart();
    }
});

function createAttackTypeChart() {
    // Get attack type data from data attribute
    const chartContainer = document.getElementById('attackTypeChart');
    const attackTypes = JSON.parse(chartContainer.getAttribute('data-attack-types'));
    
    // Prepare data for chart
    const labels = Object.keys(attackTypes);
    const data = Object.values(attackTypes);
    
    // Generate colors
    const backgroundColors = [
        'rgba(255, 99, 132, 0.2)',
        'rgba(54, 162, 235, 0.2)',
        'rgba(255, 206, 86, 0.2)',
        'rgba(75, 192, 192, 0.2)',
        'rgba(153, 102, 255, 0.2)',
        'rgba(255, 159, 64, 0.2)'
    ];
    
    const borderColors = [
        'rgba(255, 99, 132, 1)',
        'rgba(54, 162, 235, 1)',
        'rgba(255, 206, 86, 1)',
        'rgba(75, 192, 192, 1)',
        'rgba(153, 102, 255, 1)',
        'rgba(255, 159, 64, 1)'
    ];
    
    // Create chart
    const ctx = chartContainer.getContext('2d');
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColors.slice(0, labels.length),
                borderColor: borderColors.slice(0, labels.length),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#fff'
                    }
                },
                title: {
                    display: true,
                    text: 'Attack Type Distribution',
                    color: '#fff'
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.7)'
                }
            }
        }
    });
}
