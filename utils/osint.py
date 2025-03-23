import re
import json
import random
import time
import hashlib
import logging
from datetime import datetime, timedelta

def gather_data(target, data_type):
    """
    Gather OSINT data for a target
    
    Args:
        target: The target domain, IP, or email
        data_type: The type of data to gather (whois, dns, etc.)
    
    Returns:
        (success, data) tuple
    """
    try:
        # Log the request
        logging.info(f"Gathering {data_type} data for {target}")
        
        # Simulate network delay
        time.sleep(random.uniform(0.5, 1.5))
        
        # Check target format
        if data_type == 'whois':
            return gather_whois(target)
        elif data_type == 'dns':
            return gather_dns(target)
        elif data_type == 'geo':
            return gather_geo(target)
        elif data_type == 'email':
            return gather_email(target)
        elif data_type == 'headers':
            return gather_headers(target)
        elif data_type == 'ssl':
            return gather_ssl(target)
        else:
            logging.warning(f"Unsupported data type: {data_type}")
            return False, {"error": "Unsupported data type"}
    
    except Exception as e:
        logging.error(f"Error gathering OSINT data for {target}: {str(e)}")
        return False, {"error": str(e)}

def gather_whois(target):
    """
    Simulate WHOIS data gathering
    """
    # Check if it's a valid domain format
    if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$', target):
        return False, {"error": "Invalid domain format"}
    
    # Generate a random creation date in the past
    days_ago = random.randint(30, 3650)  # Between 1 month and 10 years
    creation_date = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    
    # Generate a random expiration date in the future
    days_ahead = random.randint(30, 365)  # Between 1 month and 1 year
    expiration_date = (datetime.now() + timedelta(days=days_ahead)).strftime("%Y-%m-%d")
    
    # Generate random registrar
    registrars = [
        "GoDaddy.com, LLC",
        "Namecheap, Inc.",
        "Amazon Registrar, Inc.",
        "Google LLC",
        "Network Solutions, LLC",
        "Domain.com, LLC",
        "NameSilo, LLC",
        "Cloudflare, Inc.",
        "Tucows Domains Inc."
    ]
    
    # List of states for US addresses
    states = [
        "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
        "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
        "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
        "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
        "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY"
    ]
    
    # Generate WHOIS data
    data = {
        "domain_name": target,
        "registrar": random.choice(registrars),
        "whois_server": f"whois.{random.choice(['iana.org', 'icann.org', 'verisign.com'])}",
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "updated_date": (datetime.now() - timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%d"),
        "name_servers": [
            f"ns1.{random.choice(['cloudflare.com', 'google.com', 'aws.com', 'azure.com'])}",
            f"ns2.{random.choice(['cloudflare.com', 'google.com', 'aws.com', 'azure.com'])}"
        ],
        "status": random.choice([
            "clientTransferProhibited",
            "clientUpdateProhibited",
            "clientDeleteProhibited", 
            "clientRenewProhibited"
        ]),
        "dnssec": random.choice(["unsigned", "signed"]),
        "registrant": {
            "organization": f"{target.split('.')[0].capitalize()} Organization",
            "state": random.choice(states),
            "country": "US",
            "email": f"admin@{target}"
        },
        "admin": {
            "organization": f"{target.split('.')[0].capitalize()} Admin",
            "state": random.choice(states),
            "country": "US",
            "email": f"admin@{target}"
        },
        "tech": {
            "organization": f"{target.split('.')[0].capitalize()} Tech",
            "state": random.choice(states),
            "country": "US",
            "email": f"tech@{target}"
        }
    }
    
    # Add data hash for integrity
    data_str = json.dumps(data, sort_keys=True)
    data["data_hash"] = hashlib.sha256(data_str.encode()).hexdigest()
    
    return True, data

def gather_dns(target):
    """
    Simulate DNS data gathering
    """
    # Check if it's a valid domain format
    if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$', target):
        return False, {"error": "Invalid domain format"}
    
    # Generate random IP addresses
    ip_addresses = []
    for _ in range(random.randint(1, 3)):
        ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        ip_addresses.append(ip)
    
    # Generate random MX records
    mx_records = []
    for i in range(random.randint(1, 3)):
        mx = {
            "preference": i * 10,
            "exchange": f"mail{i+1}.{target}" if random.random() < 0.7 else f"mail{i+1}.{random.choice(['google.com', 'outlook.com', 'zoho.com'])}"
        }
        mx_records.append(mx)
    
    # Generate random TXT records
    txt_records = []
    for _ in range(random.randint(0, 3)):
        txt_type = random.choice(["spf", "dkim", "verification", "other"])
        
        if txt_type == "spf":
            txt = f"v=spf1 ip4:{ip_addresses[0]} include:_spf.{random.choice(['google.com', 'outlook.com'])} ~all"
        elif txt_type == "dkim":
            txt = f"v=DKIM1; k=rsa; p={hashlib.md5(target.encode()).hexdigest()}"
        elif txt_type == "verification":
            txt = f"verification={hashlib.md5((target + 'verify').encode()).hexdigest()}"
        else:
            txt = f"random={hashlib.md5(target.encode()).hexdigest()[:16]}"
        
        txt_records.append(txt)
    
    # Generate data
    data = {
        "domain": target,
        "a_records": ip_addresses,
        "mx_records": mx_records,
        "ns_records": [
            f"ns1.{random.choice(['cloudflare.com', 'google.com', 'aws.com', 'azure.com'])}",
            f"ns2.{random.choice(['cloudflare.com', 'google.com', 'aws.com', 'azure.com'])}"
        ],
        "txt_records": txt_records,
        "cname_records": [
            {
                "name": f"www.{target}",
                "target": target
            },
            {
                "name": f"mail.{target}",
                "target": f"mail.{random.choice(['google.com', 'outlook.com']) if random.random() < 0.5 else target}"
            }
        ],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Add data hash for integrity
    data_str = json.dumps(data, sort_keys=True)
    data["data_hash"] = hashlib.sha256(data_str.encode()).hexdigest()
    
    return True, data

def gather_geo(target):
    """
    Simulate geolocation data gathering
    """
    # Check if it's a valid IP format
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        # If not an IP, assume it's a domain and generate a random IP
        ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    else:
        ip = target
    
    # List of countries and cities
    countries = [
        {"code": "US", "name": "United States", "cities": ["New York", "Los Angeles", "Chicago", "San Francisco", "Miami"]},
        {"code": "GB", "name": "United Kingdom", "cities": ["London", "Manchester", "Birmingham", "Liverpool", "Glasgow"]},
        {"code": "CA", "name": "Canada", "cities": ["Toronto", "Vancouver", "Montreal", "Calgary", "Ottawa"]},
        {"code": "AU", "name": "Australia", "cities": ["Sydney", "Melbourne", "Brisbane", "Perth", "Adelaide"]},
        {"code": "DE", "name": "Germany", "cities": ["Berlin", "Munich", "Hamburg", "Frankfurt", "Cologne"]},
        {"code": "FR", "name": "France", "cities": ["Paris", "Marseille", "Lyon", "Toulouse", "Nice"]}
    ]
    
    # Choose a random country and city
    country = random.choice(countries)
    city = random.choice(country["cities"])
    
    # Generate random latitude and longitude
    latitude = random.uniform(-90, 90)
    longitude = random.uniform(-180, 180)
    
    # Generate data
    data = {
        "ip": ip,
        "country_code": country["code"],
        "country_name": country["name"],
        "region_code": f"{country['code']}-{random.randint(1, 99):02d}",
        "region_name": f"Region {random.randint(1, 9)}",
        "city": city,
        "zip_code": f"{random.randint(10000, 99999)}",
        "latitude": latitude,
        "longitude": longitude,
        "timezone": f"GMT{random.choice(['+', '-'])}{random.randint(0, 12)}",
        "isp": random.choice([
            "Comcast Business",
            "Verizon Communications",
            "AT&T",
            "Deutsche Telekom",
            "Google LLC",
            "Amazon.com, Inc.",
            "Microsoft Corporation",
            "OVH SAS",
            "DigitalOcean, LLC"
        ]),
        "organization": f"{target.split('.')[0].capitalize() if '.' in target else 'Organization'} Ltd.",
        "as_number": f"AS{random.randint(1000, 9999)}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Add data hash for integrity
    data_str = json.dumps(data, sort_keys=True)
    data["data_hash"] = hashlib.sha256(data_str.encode()).hexdigest()
    
    return True, data

def gather_email(target):
    """
    Simulate email information gathering
    """
    # Check if it's a valid email format
    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', target):
        return False, {"error": "Invalid email format"}
    
    # Get domain from email
    domain = target.split('@')[1]
    
    # Possible services associated with the email
    services = [
        "LinkedIn",
        "Facebook",
        "Twitter",
        "Instagram",
        "GitHub",
        "HaveIBeenPwned",
        "Gravatar"
    ]
    
    # Randomly select some services
    selected_services = random.sample(services, random.randint(2, len(services)))
    
    # Generate breach data (if any)
    breach_data = []
    if random.random() < 0.3:  # 30% chance of breaches
        breach_count = random.randint(1, 3)
        for _ in range(breach_count):
            breach_data.append({
                "name": random.choice(["LinkedIn", "Adobe", "Dropbox", "Yahoo", "MySpace", "Collection #1"]),
                "date": (datetime.now() - timedelta(days=random.randint(30, 1500))).strftime("%Y-%m-%d"),
                "description": "This breach contained email addresses and hashed passwords.",
                "count": random.randint(1000000, 500000000)
            })
    
    # Generate data
    data = {
        "email": target,
        "domain": domain,
        "format": f"{target.split('@')[0].lower()}@{domain.lower()}",
        "has_mx_records": random.choice([True, True, True, False]),  # 75% chance of True
        "disposable": random.choice([True, False, False, False, False]),  # 20% chance of True
        "free_provider": any(provider in domain.lower() for provider in ["gmail", "yahoo", "hotmail", "outlook", "aol"]),
        "deliverable": random.choice([True, True, True, True, False]),  # 80% chance of True
        "services": {service: random.choice([True, False]) for service in selected_services},
        "breaches": breach_data,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Add data hash for integrity
    data_str = json.dumps(data, sort_keys=True)
    data["data_hash"] = hashlib.sha256(data_str.encode()).hexdigest()
    
    return True, data

def gather_headers(target):
    """
    Simulate HTTP headers gathering
    """
    # Check if it's a valid domain or URL format
    if not (re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$', target) or 
            re.match(r'^(http|https)://', target)):
        return False, {"error": "Invalid domain or URL format"}
    
    # Add http:// prefix if not present
    if not re.match(r'^(http|https)://', target):
        target = f"https://{target}"
    
    # Generate random headers
    server_options = ["Apache/2.4.41", "nginx/1.18.0", "Microsoft-IIS/10.0", "cloudflare", "gws (Google)", "AmazonS3"]
    x_powered_by_options = ["PHP/7.4.3", "ASP.NET", "Express", "Phusion Passenger", "PleskLin", "Node.js"]
    content_type_options = ["text/html; charset=UTF-8", "application/json", "text/plain", "application/xml"]
    
    headers = {
        "Server": random.choice(server_options),
        "Date": datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT"),
        "Content-Type": random.choice(content_type_options),
        "Transfer-Encoding": "chunked" if random.random() < 0.3 else None,
        "Connection": "keep-alive",
        "Cache-Control": random.choice(["no-cache", "max-age=3600", "must-revalidate", "no-store"]),
        "X-Powered-By": random.choice(x_powered_by_options) if random.random() < 0.4 else None,
        "X-Frame-Options": random.choice(["SAMEORIGIN", "DENY"]) if random.random() < 0.7 else None,
        "X-XSS-Protection": "1; mode=block" if random.random() < 0.7 else None,
        "X-Content-Type-Options": "nosniff" if random.random() < 0.7 else None,
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains" if random.random() < 0.6 else None,
        "Content-Security-Policy": "default-src 'self'" if random.random() < 0.4 else None,
        "Referrer-Policy": random.choice(["no-referrer", "strict-origin", "same-origin"]) if random.random() < 0.5 else None
    }
    
    # Remove None values
    headers = {k: v for k, v in headers.items() if v is not None}
    
    # Add security analysis
    security_issues = []
    security_score = 100
    
    if "X-Frame-Options" not in headers:
        security_issues.append("Missing X-Frame-Options header (clickjacking risk)")
        security_score -= 15
    
    if "X-XSS-Protection" not in headers:
        security_issues.append("Missing X-XSS-Protection header")
        security_score -= 10
    
    if "X-Content-Type-Options" not in headers:
        security_issues.append("Missing X-Content-Type-Options header")
        security_score -= 10
    
    if "Strict-Transport-Security" not in headers:
        security_issues.append("Missing HSTS header")
        security_score -= 15
    
    if "Content-Security-Policy" not in headers:
        security_issues.append("Missing Content-Security-Policy header")
        security_score -= 15
    
    if headers.get("Server") and not headers.get("Server").startswith("cloudflare"):
        security_issues.append("Server header reveals software version")
        security_score -= 10
    
    if headers.get("X-Powered-By"):
        security_issues.append("X-Powered-By header reveals technology stack")
        security_score -= 10
    
    # Generate data
    data = {
        "url": target,
        "headers": headers,
        "security_analysis": {
            "score": max(0, security_score),
            "issues": security_issues
        },
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Add data hash for integrity
    data_str = json.dumps(data, sort_keys=True)
    data["data_hash"] = hashlib.sha256(data_str.encode()).hexdigest()
    
    return True, data

def gather_ssl(target):
    """
    Simulate SSL certificate gathering
    """
    # Check if it's a valid domain format
    if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$', target):
        return False, {"error": "Invalid domain format"}
    
    # Certificate authorities
    authorities = [
        "Let's Encrypt Authority X3",
        "DigiCert SHA2 Secure Server CA",
        "GlobalSign Organization Validation CA",
        "Amazon CA",
        "Google Trust Services",
        "Sectigo RSA Domain Validation Secure Server CA"
    ]
    
    # Generate random issue/expiry dates
    days_ago = random.randint(1, 365)  # Between 1 day and 1 year
    issue_date = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    
    days_ahead = random.randint(30, 730)  # Between 1 month and 2 years
    expiry_date = (datetime.now() + timedelta(days=days_ahead)).strftime("%Y-%m-%d")
    
    # Generate signature algorithm
    signature_algorithms = ["sha256WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption"]
    
    # Generate key strength
    key_strengths = [2048, 3072, 4096]
    
    # Generate subject alternative names
    alternative_names = [
        target,
        f"www.{target}",
        f"mail.{target}" if random.random() < 0.3 else None,
        f"api.{target}" if random.random() < 0.2 else None,
        f"*.{target}" if random.random() < 0.4 else None
    ]
    
    # Remove None values
    alternative_names = [name for name in alternative_names if name]
    
    # Generate data
    data = {
        "domain": target,
        "subject": {
            "CN": target,
            "O": f"{target.split('.')[0].capitalize()} Inc." if random.random() < 0.5 else None,
            "L": random.choice(["San Francisco", "New York", "London", "Berlin", "Sydney"]) if random.random() < 0.5 else None,
            "ST": random.choice(["California", "New York", "Greater London", "Berlin", "New South Wales"]) if random.random() < 0.5 else None,
            "C": random.choice(["US", "GB", "DE", "AU", "CA"]) if random.random() < 0.5 else None
        },
        "issuer": {
            "CN": random.choice(authorities),
            "O": random.choice(["Let's Encrypt", "DigiCert Inc", "GlobalSign", "Amazon", "Google Trust Services LLC", "Sectigo Limited"]),
            "C": random.choice(["US", "GB"])
        },
        "valid_from": issue_date,
        "valid_to": expiry_date,
        "days_remaining": days_ahead,
        "serial_number": hashlib.md5(target.encode()).hexdigest(),
        "signature_algorithm": random.choice(signature_algorithms),
        "key_strength": random.choice(key_strengths),
        "subject_alternative_names": alternative_names,
        "self_signed": False if random.random() < 0.9 else True,  # 10% chance of self-signed
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Remove None values from subject
    data["subject"] = {k: v for k, v in data["subject"].items() if v is not None}
    
    # Add security analysis
    security_issues = []
    security_score = 100
    
    if data["days_remaining"] < 30:
        security_issues.append("Certificate expires in less than 30 days")
        security_score -= 30
    
    if data["key_strength"] < 2048:
        security_issues.append("Weak key strength (less than 2048 bits)")
        security_score -= 40
    
    if data["self_signed"]:
        security_issues.append("Self-signed certificate")
        security_score -= 50
    
    # Add security analysis to data
    data["security_analysis"] = {
        "score": max(0, security_score),
        "issues": security_issues
    }
    
    # Add data hash for integrity
    data_str = json.dumps(data, sort_keys=True)
    data["data_hash"] = hashlib.sha256(data_str.encode()).hexdigest()
    
    return True, data
