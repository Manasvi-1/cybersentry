# CyberSentry: AI-Powered Cybersecurity Platform

CyberSentry is an advanced cybersecurity platform that leverages artificial intelligence to detect and mitigate various cyber threats. The platform integrates honeypots, phishing detection, OSINT (Open Source Intelligence), and deepfake detection to provide comprehensive security monitoring and analysis.

## Features

- **Honeypot Management**: Deploy and monitor virtual honeypots to detect and analyze attack patterns.
- **Phishing Detection**: Analyze URLs to identify potential phishing attempts using machine learning.
- **OSINT Capabilities**: Gather intelligence from various sources about domains, IPs, and email addresses.
- **Deepfake Detection**: Detect manipulated media (images, videos, audio) using AI algorithms.
- **Threat Analysis Dashboard**: View comprehensive threat reports and analytics.
- **Alert System**: Receive notifications about security incidents.

## Technology Stack

- **Backend**: Python, Flask
- **Database**: PostgreSQL
- **AI/ML**: Scikit-learn for threat detection models
- **Frontend**: Bootstrap, Chart.js for data visualization

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Set up the PostgreSQL database
4. Configure environment variables
5. Run the application: `python main.py`

## Usage

1. Register an account and log in
2. Navigate to the dashboard to access different security features
3. Set up honeypots, analyze phishing URLs, gather OSINT data, or detect deepfakes
4. View threat analysis reports and alerts

## Security Notes

- This application is for demonstration and educational purposes
- The honeypot functionality is simulated and doesn't set up actual network traps
- Deepfake detection uses simplified algorithms for demonstration

## License

MIT License