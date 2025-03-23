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
    
    // Validate file content
    const deepfakeForm = document.getElementById('deepfake-form');
    if (deepfakeForm) {
        deepfakeForm.addEventListener('submit', function(e) {
            const fileContentInput = document.getElementById('file_content');
            const filenameInput = document.getElementById('filename');
            
            if (!fileContentInput.value.trim()) {
                e.preventDefault();
                const errorElement = document.getElementById('file-error');
                errorElement.textContent = 'Please provide file content';
                errorElement.classList.remove('d-none');
                fileContentInput.classList.add('is-invalid');
            }
            
            if (!filenameInput.value.trim()) {
                e.preventDefault();
                const errorElement = document.getElementById('filename-error');
                errorElement.textContent = 'Please provide a filename';
                errorElement.classList.remove('d-none');
                filenameInput.classList.add('is-invalid');
            }
        });
        
        // Clear errors on input change
        const fileContentInput = document.getElementById('file_content');
        if (fileContentInput) {
            fileContentInput.addEventListener('input', function() {
                const errorElement = document.getElementById('file-error');
                errorElement.classList.add('d-none');
                fileContentInput.classList.remove('is-invalid');
            });
        }
        
        const filenameInput = document.getElementById('filename');
        if (filenameInput) {
            filenameInput.addEventListener('input', function() {
                const errorElement = document.getElementById('filename-error');
                errorElement.classList.add('d-none');
                filenameInput.classList.remove('is-invalid');
            });
        }
    }
    
    // File upload handling
    const fileUploadInput = document.getElementById('file-upload');
    if (fileUploadInput) {
        fileUploadInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(event) {
                    // Get base64 content (remove the data:xxx;base64, prefix)
                    const base64Content = event.target.result.split(',')[1];
                    
                    // Set the content to the hidden input
                    document.getElementById('file_content').value = base64Content;
                    document.getElementById('filename').value = file.name;
                    
                    // Show file info
                    document.getElementById('file-info').textContent = `File selected: ${file.name} (${formatBytes(file.size)})`;
                    document.getElementById('file-info').classList.remove('d-none');
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    // Create deepfake stats chart if element exists
    const deepfakeStatsElement = document.getElementById('deepfakeStatsChart');
    if (deepfakeStatsElement) {
        createDeepfakeStatsChart();
    }
});

// Format bytes to human-readable format
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function createDeepfakeStatsChart() {
    // Get data from data attributes
    const chartElement = document.getElementById('deepfakeStatsChart');
    const deepfakeCount = parseInt(chartElement.getAttribute('data-deepfake-count'));
    const authenticCount = parseInt(chartElement.getAttribute('data-authentic-count'));
    const mediaTypes = JSON.parse(chartElement.getAttribute('data-media-types'));
    
    // Create detection result pie chart
    const resultCtx = document.getElementById('resultChart').getContext('2d');
    new Chart(resultCtx, {
        type: 'pie',
        data: {
            labels: ['Deepfake', 'Authentic'],
            datasets: [{
                data: [deepfakeCount, authenticCount],
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
                    text: 'Deepfake Detection Results',
                    color: '#fff'
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.7)'
                }
            }
        }
    });
    
    // Create media type distribution chart
    if (mediaTypes) {
        const typeCtx = document.getElementById('mediaTypeChart').getContext('2d');
        new Chart(typeCtx, {
            type: 'bar',
            data: {
                labels: Object.keys(mediaTypes),
                datasets: [{
                    label: 'Count',
                    data: Object.values(mediaTypes),
                    backgroundColor: [
                        'rgba(54, 162, 235, 0.2)',
                        'rgba(153, 102, 255, 0.2)',
                        'rgba(255, 159, 64, 0.2)'
                    ],
                    borderColor: [
                        'rgba(54, 162, 235, 1)',
                        'rgba(153, 102, 255, 1)',
                        'rgba(255, 159, 64, 1)'
                    ],
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
                        text: 'Media Type Distribution',
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
}

// Display confidence as a progress bar
document.querySelectorAll('[id^="confidence-bar-"]').forEach(bar => {
    const confidence = parseFloat(bar.getAttribute('data-confidence'));
    const id = bar.getAttribute('data-id');
    
    // Set progress bar width
    bar.style.width = `${confidence * 100}%`;
    bar.setAttribute('aria-valuenow', confidence * 100);
    
    // Set color based on confidence
    if (confidence > 0.8) {
        bar.classList.add('bg-danger');
    } else if (confidence > 0.5) {
        bar.classList.add('bg-warning');
    } else {
        bar.classList.add('bg-info');
    }
});
