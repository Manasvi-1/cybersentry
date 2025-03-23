import re
import urllib.parse
from sklearn.linear_model import LogisticRegression
import numpy as np
import random
import string
import logging

# Initialize a model for phishing detection
phishing_model = LogisticRegression()

# Some suspicious keywords that often appear in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'banking', 'secure', 'account', 'update', 
    'confirm', 'password', 'credential', 'wallet', 'alert', 'paypal', 'apple',
    'microsoft', 'google', 'facebook', 'authenticate', 'verification'
]

# Initialize the model with some basic rules
# This is a simplified approach for demonstration purposes
def initialize_model():
    # Generate some synthetic training data
    # In a real application, this would use a proper dataset
    X_train = []
    y_train = []
    
    # Generate positive examples (phishing URLs)
    for _ in range(100):
        features = [
            random.random() * 0.7 + 0.3,  # High number of suspicious words
            random.random() * 0.7 + 0.3,  # High number of special chars
            random.random() * 0.7,        # Short domain age
            random.random() * 0.7,        # Short URL lifespan
            random.random() * 0.7 + 0.3,  # Many subdomains
            random.random() * 0.7 + 0.3,  # Has IP address
            random.random() * 0.7 + 0.3,  # Has URL shortening
            random.random() * 0.7         # Few domain tokens
        ]
        X_train.append(features)
        y_train.append(1)  # 1 for phishing
    
    # Generate negative examples (legitimate URLs)
    for _ in range(100):
        features = [
            random.random() * 0.3,        # Low number of suspicious words
            random.random() * 0.3,        # Low number of special chars
            random.random() * 0.7 + 0.3,  # Long domain age
            random.random() * 0.7 + 0.3,  # Long URL lifespan
            random.random() * 0.3,        # Few subdomains
            random.random() * 0.3,        # No IP address
            random.random() * 0.3,        # No URL shortening
            random.random() * 0.7 + 0.3   # Many domain tokens
        ]
        X_train.append(features)
        y_train.append(0)  # 0 for legitimate
    
    # Train the model
    phishing_model.fit(X_train, y_train)
    logging.debug("Phishing detection model initialized")

# Initialize the model
initialize_model()

def extract_features(url):
    """
    Extract features from a URL for phishing detection
    
    Args:
        url: The URL to analyze
    
    Returns:
        Dictionary of extracted features
    """
    try:
        # Parse the URL
        parsed_url = urllib.parse.urlparse(url)
        
        # Extract domain parts
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        
        # Count suspicious words in the URL
        suspicious_word_count = sum(1 for word in SUSPICIOUS_KEYWORDS if word in url.lower())
        
        # Count special characters
        special_char_count = sum(1 for char in url if not char.isalnum() and char not in ['.', '/', '-', '_'])
        
        # Count subdomains
        subdomain_count = domain.count('.')
        
        # Check for IP address instead of domain name
        has_ip = bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain))
        
        # Check for URL shortening services
        shortening_services = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly']
        is_shortened = any(service in domain for service in shortening_services)
        
        # Count tokens in the domain (excluding subdomains)
        main_domain = domain.split('.')[-2] if subdomain_count > 0 else domain
        domain_token_count = len(re.findall(r'[a-zA-Z0-9]+', main_domain))
        
        # Ratio of digits to characters in domain
        digit_count = sum(1 for char in domain if char.isdigit())
        char_count = sum(1 for char in domain if char.isalpha())
        digit_ratio = digit_count / (char_count + 1)  # Add 1 to avoid division by zero
        
        # URL length
        url_length = len(url)
        
        # Path length
        path_length = len(path)
        
        # Query parameters count
        query_param_count = len(query.split('&')) if query else 0
        
        return {
            'suspicious_word_count': suspicious_word_count,
            'special_char_count': special_char_count,
            'subdomain_count': subdomain_count,
            'has_ip': has_ip,
            'is_shortened': is_shortened,
            'domain_token_count': domain_token_count,
            'digit_ratio': digit_ratio,
            'url_length': url_length,
            'path_length': path_length,
            'query_param_count': query_param_count
        }
    
    except Exception as e:
        logging.error(f"Error extracting features from URL {url}: {str(e)}")
        # Return default values if extraction fails
        return {
            'suspicious_word_count': 0,
            'special_char_count': 0,
            'subdomain_count': 0,
            'has_ip': False,
            'is_shortened': False,
            'domain_token_count': 0,
            'digit_ratio': 0,
            'url_length': len(url),
            'path_length': 0,
            'query_param_count': 0
        }

def analyze_url(url, features):
    """
    Analyze a URL to determine if it's a phishing attempt
    
    Args:
        url: The URL to analyze
        features: Dictionary of extracted features
    
    Returns:
        (is_phishing, confidence) tuple
    """
    try:
        # Prepare features in the correct order for the model
        feature_vector = [
            features['suspicious_word_count'] / 5,  # Normalize
            features['special_char_count'] / 10,    # Normalize
            random.random() * 0.5,                  # Domain age (simulated)
            random.random() * 0.5,                  # URL lifespan (simulated)
            features['subdomain_count'] / 3,        # Normalize
            1.0 if features['has_ip'] else 0.0,
            1.0 if features['is_shortened'] else 0.0,
            1.0 / (features['domain_token_count'] + 1)  # Inverse (smaller is worse)
        ]
        
        # Make prediction
        prediction = phishing_model.predict([feature_vector])[0]
        confidence = phishing_model.predict_proba([feature_vector])[0][prediction]
        
        # High number of suspicious words is a strong indicator
        if features['suspicious_word_count'] >= 3:
            confidence = max(confidence, 0.75)
        
        # Having an IP address in the URL is a strong indicator
        if features['has_ip']:
            confidence = max(confidence, 0.8)
        
        # URL shorteners can be suspicious
        if features['is_shortened']:
            confidence = max(confidence, 0.6)
        
        # Excessively long URLs can be suspicious
        if features['url_length'] > 100:
            confidence = max(confidence, 0.7)
        
        return bool(prediction), float(confidence)
    
    except Exception as e:
        logging.error(f"Error analyzing URL {url}: {str(e)}")
        # Return a conservative result in case of error
        return False, 0.0
