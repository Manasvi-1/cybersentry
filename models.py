from app import db
from flask_login import UserMixin
from datetime import datetime
import hashlib
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    honeypots = db.relationship('Honeypot', backref='user', lazy=True)
    alerts = db.relationship('Alert', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Honeypot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(256))
    ip_address = db.Column(db.String(64))
    port = db.Column(db.Integer)
    service_type = db.Column(db.String(64))  # HTTP, FTP, SSH, etc.
    status = db.Column(db.String(16), default='active')  # active, inactive
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    attacks = db.relationship('HoneypotAttack', backref='honeypot', lazy=True)
    
    def __repr__(self):
        return f'<Honeypot {self.name}>'

class HoneypotAttack(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    attack_type = db.Column(db.String(64))
    request_data = db.Column(db.Text)  # Stores the full request as text
    honeypot_id = db.Column(db.Integer, db.ForeignKey('honeypot.id'), nullable=False)
    
    def __repr__(self):
        return f'<Attack {self.source_ip} on {self.honeypot_id}>'
    
    def data_integrity_check(self):
        """Generate a hash of the attack data for integrity verification"""
        hash_input = f"{self.source_ip}{self.timestamp}{self.attack_type}{self.request_data}{self.honeypot_id}"
        return hashlib.sha256(hash_input.encode()).hexdigest()

class PhishingUrl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(256), nullable=False)
    is_phishing = db.Column(db.Boolean)
    confidence = db.Column(db.Float)  # ML model confidence score
    features = db.Column(db.Text)  # JSON string of extracted features
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PhishingURL {self.url[:30]}...>'
    
    def set_features(self, features_dict):
        """Store features as JSON string"""
        self.features = json.dumps(features_dict)
    
    def get_features(self):
        """Retrieve features as dictionary"""
        return json.loads(self.features) if self.features else {}

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(16))  # high, medium, low
    source = db.Column(db.String(64))  # honeypot, phishing detection, etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<Alert {self.title}>'

class OsintData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(128), nullable=False)  # Domain, IP, etc.
    data_type = db.Column(db.String(64))  # whois, dns, etc.
    data = db.Column(db.Text)  # JSON string of collected data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<OSINT {self.target} - {self.data_type}>'
    
    def set_data(self, data_dict):
        """Store data as JSON string"""
        self.data = json.dumps(data_dict)
    
    def get_data(self):
        """Retrieve data as dictionary"""
        return json.loads(self.data) if self.data else {}
    
    def data_integrity_check(self):
        """Generate a hash of the OSINT data for integrity verification"""
        return hashlib.sha256(self.data.encode()).hexdigest()

class DeepfakeDetection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_hash = db.Column(db.String(64), nullable=False)  # SHA-256 hash of the file
    filename = db.Column(db.String(128))
    media_type = db.Column(db.String(16))  # image, video, audio
    is_deepfake = db.Column(db.Boolean)
    confidence = db.Column(db.Float)  # ML model confidence score
    features = db.Column(db.Text)  # JSON string of extracted features
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<DeepfakeDetection {self.filename}>'
    
    def set_features(self, features_dict):
        """Store features as JSON string"""
        self.features = json.dumps(features_dict)
    
    def get_features(self):
        """Retrieve features as dictionary"""
        return json.loads(self.features) if self.features else {}
