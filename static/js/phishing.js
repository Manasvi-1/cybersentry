document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    
    // Toggle feature details
    const toggleButtons = document.querySelectorAll('.toggle-features');
    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const targetId = this.getAttribute('data-target');
            const targetElement = document.getElementById(targetId);
            
            if (targetElement.classList.contains('d-none')) {
                targetElement.classList.remove('d-none');
                this.innerHTML = '<i class="bi bi-chevron-up"></i> Hide Features';
            } else {
                targetElement.classList.add('d-none');
                this.innerHTML = '<i class="bi bi-chevron-down"></i> Show Features';
            }
        });
    });
    
    // URL analysis form validation
    const urlForm = document.getElementById('phishing-form');
    if (urlForm) {
        urlForm.addEventListener('submit', function(e) {
            const urlInput = document.getElementById('url');
            const url = urlInput.value.trim();
            
            // Basic URL validation
            const urlPattern = /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([\/\w .-]*)*\/?$/;
            
            if (!urlPattern.test(url)) {
                e.preventDefault();
                const errorElement = document.getElementById('url-error');
                errorElement.textContent = 'Please enter a valid URL';
                errorElement.classList.remove('d-none');
                urlInput.classList.add('is-invalid');
            }
        });
        
        // Clear error on input change
        const urlInput = document.getElementById('url');
        if (urlInput) {
            urlInput.addEventListener('input', function() {
                const errorElement = document.getElementById('url-error');
                errorElement.classList.add('d-none');
                urlInput.classList.remove('is-invalid');
            });
        }
    }
    
    // Create phishing stats chart if element exists
    const phishingStatsElement = document.getElementById('phishingStatsChart');
    if (phishingStatsElement) {
        createPhishingStatsChart();
    }
});

function createPhishingStatsChart() {
    // Get data from data attributes
    const chartElement = document.getElementById('phishingStatsChart');
    const phishingCount = parseInt(chartElement.getAttribute('data-phishing-count'));
    const legitimateCount = parseInt(chartElement.getAttribute('data-legitimate-count'));
    
    // Create chart
    const ctx = chartElement.getContext('2d');
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Phishing', 'Legitimate'],
            datasets: [{
                data: [phishingCount, legitimateCount],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.2)',
                    'rgba(75, 192, 192, 0.2)'
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(75, 192, 192, 1)'
                ],
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
                    text: 'Phishing Detection Results',
                    color: '#fff'
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.7)'
                }
            }
        }
    });
}

// Display confidence as a progress bar
function updateConfidenceBar(urlId, confidence) {
    const progressBar = document.getElementById(`confidence-bar-${urlId}`);
    if (progressBar) {
        progressBar.style.width = `${confidence * 100}%`;
        progressBar.setAttribute('aria-valuenow', confidence * 100);
        
        // Set color based on confidence
        if (confidence > 0.8) {
            progressBar.classList.add('bg-danger');
        } else if (confidence > 0.5) {
            progressBar.classList.add('bg-warning');
        } else {
            progressBar.classList.add('bg-info');
        }
    }
}

// Initialize all confidence bars
document.querySelectorAll('[id^="confidence-bar-"]').forEach(bar => {
    const confidence = parseFloat(bar.getAttribute('data-confidence'));
    const urlId = bar.getAttribute('data-url-id');
    updateConfidenceBar(urlId, confidence);
});
