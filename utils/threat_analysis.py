import random
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import hashlib
import json

def generate_threat_report(attacks, phishing_urls, deepfakes):
    """
    Generate a comprehensive threat analysis report
    
    Args:
        attacks: List of HoneypotAttack objects
        phishing_urls: List of PhishingUrl objects
        deepfakes: List of DeepfakeDetection objects
    
    Returns:
        Dictionary containing threat analysis report
    """
    # Initialize report structure
    report = {
        "summary": {
            "total_attacks": len(attacks),
            "total_phishing": len(phishing_urls),
            "total_deepfakes": len(deepfakes),
            "risk_level": "Unknown",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "attack_analysis": {},
        "phishing_analysis": {},
        "deepfake_analysis": {},
        "indicators_of_compromise": [],
        "recommendations": [],
        "data_integrity": ""
    }
    
    # Perform attack analysis if we have attack data
    if attacks:
        # Count attacks by type
        attack_types = Counter([attack.attack_type for attack in attacks])
        most_common_type = attack_types.most_common(1)[0][0] if attack_types else "N/A"
        
        # Count attacks by source IP
        source_ips = Counter([attack.source_ip for attack in attacks])
        most_active_sources = [ip for ip, count in source_ips.most_common(5)]
        
        # Check for attack patterns over time
        attack_times = [attack.timestamp for attack in attacks]
        
        # Group attacks by day
        attack_days = defaultdict(int)
        for timestamp in attack_times:
            day = timestamp.strftime('%Y-%m-%d')
            attack_days[day] += 1
        
        # Calculate attack rate (attacks per day)
        if attack_times:
            date_range = (max(attack_times) - min(attack_times)).days + 1
            attack_rate = len(attacks) / max(1, date_range)  # Avoid division by zero
        else:
            attack_rate = 0
        
        # Find attack spikes
        avg_attacks_per_day = len(attacks) / max(1, len(attack_days))
        spike_days = [day for day, count in attack_days.items() if count > 2 * avg_attacks_per_day]
        
        # Add attack analysis to report
        report["attack_analysis"] = {
            "attack_types": dict(attack_types),
            "most_common_type": most_common_type,
            "most_active_sources": most_active_sources,
            "attack_rate": round(attack_rate, 2),
            "attack_spikes": spike_days,
            "patterns_detected": len(spike_days) > 0
        }
        
        # Add IoCs based on attack data
        for ip, count in source_ips.most_common(3):
            report["indicators_of_compromise"].append({
                "type": "ip_address",
                "value": ip,
                "confidence": "high" if count > 5 else "medium",
                "source": "honeypot"
            })
    
    # Perform phishing analysis if we have phishing data
    if phishing_urls:
        # Extract domains from URLs
        domains = []
        for url_obj in phishing_urls:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url_obj.url).netloc
                domains.append(domain)
            except:
                pass
        
        # Count occurrences of each domain
        domain_counts = Counter(domains)
        most_common_domains = [domain for domain, count in domain_counts.most_common(5)]
        
        # Calculate average confidence score
        avg_confidence = sum(url.confidence for url in phishing_urls) / len(phishing_urls)
        
        # Add phishing analysis to report
        report["phishing_analysis"] = {
            "targeted_domains": dict(domain_counts),
            "most_common_domains": most_common_domains,
            "average_confidence": round(avg_confidence, 2),
            "high_confidence_detections": sum(1 for url in phishing_urls if url.confidence > 0.8)
        }
        
        # Add IoCs based on phishing data
        for domain, count in domain_counts.most_common(3):
            report["indicators_of_compromise"].append({
                "type": "domain",
                "value": domain,
                "confidence": "high" if count > 2 else "medium",
                "source": "phishing_detection"
            })
    
    # Perform deepfake analysis if we have deepfake data
    if deepfakes:
        # Count by media type
        media_types = Counter([df.media_type for df in deepfakes])
        
        # Calculate average confidence score
        avg_confidence = sum(df.confidence for df in deepfakes) / len(deepfakes)
        
        # Add deepfake analysis to report
        report["deepfake_analysis"] = {
            "media_types": dict(media_types),
            "average_confidence": round(avg_confidence, 2),
            "high_confidence_detections": sum(1 for df in deepfakes if df.confidence > 0.8)
        }
    
    # Determine overall risk level
    risk_score = 0
    
    # Risk from attacks
    if attacks:
        attack_risk = min(10, len(attacks) / 10)  # Cap at 10
        risk_score += attack_risk
        
        # Additional risk for specific attack types
        if any(attack.attack_type in ["SQL Injection", "Command Injection"] for attack in attacks):
            risk_score += 5
    
    # Risk from phishing
    if phishing_urls:
        phishing_risk = min(10, len(phishing_urls) / 2)  # Cap at 10
        risk_score += phishing_risk
        
        # Additional risk for high confidence phishing
        high_conf_phishing = sum(1 for url in phishing_urls if url.confidence > 0.8)
        if high_conf_phishing > 0:
            risk_score += min(5, high_conf_phishing)
    
    # Risk from deepfakes
    if deepfakes:
        deepfake_risk = min(10, len(deepfakes) * 2)  # Cap at 10
        risk_score += deepfake_risk
    
    # Determine risk level
    if risk_score >= 20:
        risk_level = "Critical"
    elif risk_score >= 15:
        risk_level = "High"
    elif risk_score >= 10:
        risk_level = "Medium"
    elif risk_score >= 5:
        risk_level = "Low"
    else:
        risk_level = "Minimal"
    
    report["summary"]["risk_level"] = risk_level
    report["summary"]["risk_score"] = round(risk_score, 2)
    
    # Generate recommendations based on findings
    if attacks:
        if any(attack.attack_type == "SQL Injection" for attack in attacks):
            report["recommendations"].append({
                "priority": "high",
                "title": "Strengthen SQL Injection Defenses",
                "description": "Implement parameterized queries and input validation to prevent SQL injection attacks."
            })
        
        if any(attack.attack_type == "Bruteforce" for attack in attacks):
            report["recommendations"].append({
                "priority": "high",
                "title": "Implement Account Lockout Policies",
                "description": "Add account lockout after multiple failed login attempts to prevent brute force attacks."
            })
    
    if phishing_urls:
        report["recommendations"].append({
            "priority": "medium",
            "title": "Employee Phishing Training",
            "description": "Conduct regular phishing awareness training for all employees."
        })
    
    if deepfakes:
        report["recommendations"].append({
            "priority": "medium",
            "title": "Media Verification Protocol",
            "description": "Implement a verification protocol for sensitive media to detect potential deepfakes."
        })
    
    # Add general security recommendations
    report["recommendations"].append({
        "priority": "medium",
        "title": "Regular Security Audits",
        "description": "Conduct regular security audits and penetration testing to identify vulnerabilities."
    })
    
    report["recommendations"].append({
        "priority": "low",
        "title": "Security Monitoring",
        "description": "Implement continuous security monitoring and threat hunting to detect and respond to threats."
    })
    
    # Calculate a hash of the report for data integrity
    report_str = json.dumps(report, sort_keys=True)
    report["data_integrity"] = hashlib.sha256(report_str.encode()).hexdigest()
    
    return report
