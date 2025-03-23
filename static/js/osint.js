document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    
    // OSINT form validation
    const osintForm = document.getElementById('osint-form');
    if (osintForm) {
        osintForm.addEventListener('submit', function(e) {
            const targetInput = document.getElementById('target');
            const target = targetInput.value.trim();
            const dataType = document.getElementById('data_type').value;
            
            // Validation patterns for different data types
            const patterns = {
                'whois': /^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$/,
                'dns': /^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$/,
                'geo': /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)$/,
                'email': /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/,
                'headers': /^(http|https):\/\/[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+/,
                'ssl': /^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$/
            };
            
            if (!patterns[dataType].test(target)) {
                e.preventDefault();
                const errorElement = document.getElementById('target-error');
                errorElement.textContent = `Please enter a valid ${dataType === 'geo' ? 'domain or IP address' : dataType}`;
                errorElement.classList.remove('d-none');
                targetInput.classList.add('is-invalid');
            }
        });
        
        // Clear error on input change
        const targetInput = document.getElementById('target');
        if (targetInput) {
            targetInput.addEventListener('input', function() {
                const errorElement = document.getElementById('target-error');
                errorElement.classList.add('d-none');
                targetInput.classList.remove('is-invalid');
            });
        }
        
        // Update validation pattern when data type changes
        const dataTypeSelect = document.getElementById('data_type');
        if (dataTypeSelect) {
            dataTypeSelect.addEventListener('change', function() {
                const dataType = this.value;
                const targetInput = document.getElementById('target');
                
                // Update placeholder based on data type
                switch (dataType) {
                    case 'whois':
                        targetInput.setAttribute('placeholder', 'example.com');
                        break;
                    case 'dns':
                        targetInput.setAttribute('placeholder', 'example.com');
                        break;
                    case 'geo':
                        targetInput.setAttribute('placeholder', 'example.com or 8.8.8.8');
                        break;
                    case 'email':
                        targetInput.setAttribute('placeholder', 'user@example.com');
                        break;
                    case 'headers':
                        targetInput.setAttribute('placeholder', 'https://example.com');
                        break;
                    case 'ssl':
                        targetInput.setAttribute('placeholder', 'example.com');
                        break;
                }
            });
        }
    }
    
    // Toggle JSON data display
    const toggleButtons = document.querySelectorAll('.toggle-json');
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const targetElement = document.getElementById(targetId);
            
            if (targetElement.classList.contains('d-none')) {
                targetElement.classList.remove('d-none');
                this.innerHTML = '<i class="bi bi-chevron-up"></i> Hide Raw Data';
            } else {
                targetElement.classList.add('d-none');
                this.innerHTML = '<i class="bi bi-chevron-down"></i> Show Raw Data';
            }
        });
    });
    
    // Format JSON displays for better readability
    document.querySelectorAll('.json-display').forEach(element => {
        try {
            const jsonData = JSON.parse(element.textContent);
            element.textContent = JSON.stringify(jsonData, null, 2);
        } catch (e) {
            console.error('Error formatting JSON:', e);
        }
    });
    
    // Create OSINT data type distribution chart if element exists
    const osintChartElement = document.getElementById('osintTypeChart');
    if (osintChartElement) {
        createOsintTypeChart();
    }
});

function createOsintTypeChart() {
    // Get data from data attributes
    const chartElement = document.getElementById('osintTypeChart');
    const dataTypes = JSON.parse(chartElement.getAttribute('data-types'));
    
    // Prepare data for chart
    const labels = Object.keys(dataTypes);
    const data = Object.values(dataTypes);
    
    // Generate colors
    const backgroundColors = [
        'rgba(75, 192, 192, 0.2)',
        'rgba(255, 99, 132, 0.2)',
        'rgba(54, 162, 235, 0.2)',
        'rgba(255, 206, 86, 0.2)',
        'rgba(153, 102, 255, 0.2)',
        'rgba(255, 159, 64, 0.2)'
    ];
    
    const borderColors = [
        'rgba(75, 192, 192, 1)',
        'rgba(255, 99, 132, 1)',
        'rgba(54, 162, 235, 1)',
        'rgba(255, 206, 86, 1)',
        'rgba(153, 102, 255, 1)',
        'rgba(255, 159, 64, 1)'
    ];
    
    // Create chart
    const ctx = chartElement.getContext('2d');
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Count',
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
                    display: false
                },
                title: {
                    display: true,
                    text: 'OSINT Data Collection by Type',
                    color: '#fff'
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
