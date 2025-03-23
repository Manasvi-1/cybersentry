from flask import render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging
import os
import json
import hashlib
from datetime import datetime, timedelta

from app import app, db
from models import User, Honeypot, HoneypotAttack, PhishingUrl, Alert, OsintData, DeepfakeDetection
from forms import LoginForm, RegistrationForm, HoneypotForm, PhishingUrlForm, OsintForm, DeepfakeForm
from utils.honeypot import simulate_attack, create_honeypot
from utils.phishing import analyze_url, extract_features
from utils.osint import gather_data
from utils.deepfake import detect_deepfake
from utils.threat_analysis import generate_threat_report

# Home page
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# User authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user_exists = User.query.filter_by(username=form.username.data).first()
        email_exists = User.query.filter_by(email=form.email.data).first()
        
        if user_exists:
            flash('Username already taken', 'danger')
        elif email_exists:
            flash('Email already registered', 'danger')
        else:
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent alerts
    recent_alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.timestamp.desc()).limit(5).all()
    
    # Get honeypot stats
    honeypots = Honeypot.query.filter_by(user_id=current_user.id).all()
    honeypot_count = len(honeypots)
    
    honeypot_ids = [h.id for h in honeypots]
    attack_count = HoneypotAttack.query.filter(HoneypotAttack.honeypot_id.in_(honeypot_ids)).count() if honeypot_ids else 0
    
    # Get phishing detection stats
    phishing_count = PhishingUrl.query.filter_by(is_phishing=True).count()
    
    # Get OSINT stats
    osint_count = OsintData.query.count()
    
    # Get deepfake detection stats
    deepfake_count = DeepfakeDetection.query.filter_by(is_deepfake=True).count()
    
    # Generate attack time series data for the chart
    now = datetime.utcnow()
    past_week = now - timedelta(days=7)
    
    # If we have honeypots, get attack data for the past week
    attack_data = []
    if honeypot_ids:
        attacks = HoneypotAttack.query.filter(
            HoneypotAttack.honeypot_id.in_(honeypot_ids),
            HoneypotAttack.timestamp >= past_week
        ).all()
        
        # Group attacks by day
        attack_days = {}
        for attack in attacks:
            day = attack.timestamp.strftime('%Y-%m-%d')
            if day in attack_days:
                attack_days[day] += 1
            else:
                attack_days[day] = 1
        
        # Format data for chart.js
        for i in range(7):
            day = (now - timedelta(days=i)).strftime('%Y-%m-%d')
            attack_data.append({
                'date': day,
                'count': attack_days.get(day, 0)
            })
        
        attack_data.reverse()  # So it's in chronological order
    
    return render_template(
        'dashboard.html', 
        recent_alerts=recent_alerts,
        honeypot_count=honeypot_count,
        attack_count=attack_count,
        phishing_count=phishing_count,
        osint_count=osint_count,
        deepfake_count=deepfake_count,
        attack_data=json.dumps(attack_data)
    )

# Honeypot routes
@app.route('/honeypot')
@login_required
def honeypot_dashboard():
    honeypots = Honeypot.query.filter_by(user_id=current_user.id).all()
    
    # Get attacks for each honeypot
    honeypot_data = []
    for honeypot in honeypots:
        attacks = HoneypotAttack.query.filter_by(honeypot_id=honeypot.id).order_by(HoneypotAttack.timestamp.desc()).limit(5).all()
        attack_count = HoneypotAttack.query.filter_by(honeypot_id=honeypot.id).count()
        
        honeypot_data.append({
            'honeypot': honeypot,
            'attacks': attacks,
            'attack_count': attack_count
        })
    
    return render_template('honeypot.html', honeypot_data=honeypot_data, form=HoneypotForm())

@app.route('/honeypot/create', methods=['POST'])
@login_required
def create_honeypot_route():
    form = HoneypotForm()
    if form.validate_on_submit():
        honeypot = Honeypot(
            name=form.name.data,
            description=form.description.data,
            ip_address=form.ip_address.data,
            port=form.port.data,
            service_type=form.service_type.data,
            user_id=current_user.id
        )
        db.session.add(honeypot)
        db.session.commit()
        
        # Create a simulated honeypot in our simplified environment
        create_honeypot(honeypot)
        
        flash(f'Honeypot {form.name.data} has been created successfully!', 'success')
        return redirect(url_for('honeypot_dashboard'))
    
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text}: {error}", 'danger')
    
    return redirect(url_for('honeypot_dashboard'))

@app.route('/honeypot/<int:honeypot_id>/delete', methods=['POST'])
@login_required
def delete_honeypot(honeypot_id):
    honeypot = Honeypot.query.get_or_404(honeypot_id)
    
    # Check if user owns this honeypot
    if honeypot.user_id != current_user.id:
        flash('You do not have permission to delete this honeypot', 'danger')
        return redirect(url_for('honeypot_dashboard'))
    
    # Delete associated attacks first (to maintain referential integrity)
    HoneypotAttack.query.filter_by(honeypot_id=honeypot.id).delete()
    
    # Delete the honeypot
    db.session.delete(honeypot)
    db.session.commit()
    
    flash(f'Honeypot {honeypot.name} has been deleted', 'success')
    return redirect(url_for('honeypot_dashboard'))

@app.route('/honeypot/<int:honeypot_id>/simulate_attack', methods=['POST'])
@login_required
def simulate_honeypot_attack(honeypot_id):
    honeypot = Honeypot.query.get_or_404(honeypot_id)
    
    # Check if user owns this honeypot
    if honeypot.user_id != current_user.id:
        flash('You do not have permission to simulate attacks on this honeypot', 'danger')
        return redirect(url_for('honeypot_dashboard'))
    
    # Simulate an attack
    attack = simulate_attack(honeypot)
    
    # Create a new alert for this attack
    alert = Alert(
        title=f"Attack detected on {honeypot.name}",
        description=f"Attack from {attack.source_ip} detected. Type: {attack.attack_type}",
        severity="medium",
        source="honeypot",
        user_id=current_user.id
    )
    db.session.add(alert)
    db.session.commit()
    
    flash(f'Attack simulated on {honeypot.name}', 'success')
    return redirect(url_for('honeypot_dashboard'))

# Phishing URL detection routes
@app.route('/phishing')
@login_required
def phishing_dashboard():
    # Get recent phishing URLs
    recent_urls = PhishingUrl.query.order_by(PhishingUrl.created_at.desc()).limit(10).all()
    
    return render_template('phishing.html', 
                          recent_urls=recent_urls, 
                          form=PhishingUrlForm())

@app.route('/phishing/analyze', methods=['POST'])
@login_required
def analyze_phishing_url():
    form = PhishingUrlForm()
    if form.validate_on_submit():
        url = form.url.data
        
        # Check if URL has already been analyzed
        existing_url = PhishingUrl.query.filter_by(url=url).first()
        if existing_url:
            flash(f"This URL has already been analyzed. Result: {'Phishing' if existing_url.is_phishing else 'Legitimate'}", 'info')
            return redirect(url_for('phishing_dashboard'))
        
        # Extract features
        features = extract_features(url)
        
        # Analyze the URL
        is_phishing, confidence = analyze_url(url, features)
        
        # Save the result
        phishing_url = PhishingUrl(
            url=url,
            is_phishing=is_phishing,
            confidence=confidence
        )
        phishing_url.set_features(features)
        db.session.add(phishing_url)
        
        # Create an alert if it's a phishing URL
        if is_phishing:
            alert = Alert(
                title=f"Phishing URL detected",
                description=f"URL: {url} - Confidence: {confidence:.2f}",
                severity="high" if confidence > 0.8 else "medium",
                source="phishing_detection",
                user_id=current_user.id
            )
            db.session.add(alert)
        
        db.session.commit()
        
        result = "Phishing" if is_phishing else "Legitimate"
        flash(f'URL analysis complete. Result: {result} (Confidence: {confidence:.2f})', 'success')
        return redirect(url_for('phishing_dashboard'))
    
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text}: {error}", 'danger')
    
    return redirect(url_for('phishing_dashboard'))

# OSINT routes
@app.route('/osint')
@login_required
def osint_dashboard():
    # Get recent OSINT data
    recent_data = OsintData.query.order_by(OsintData.created_at.desc()).limit(10).all()
    
    return render_template('osint.html', 
                          recent_data=recent_data, 
                          form=OsintForm())

@app.route('/osint/gather', methods=['POST'])
@login_required
def gather_osint_data():
    form = OsintForm()
    if form.validate_on_submit():
        target = form.target.data
        data_type = form.data_type.data
        
        # Gather OSINT data
        result, data = gather_data(target, data_type)
        
        if result:
            # Save the result
            osint_data = OsintData(
                target=target,
                data_type=data_type
            )
            osint_data.set_data(data)
            db.session.add(osint_data)
            db.session.commit()
            
            flash(f'OSINT data collection complete for {target}', 'success')
        else:
            flash(f'Failed to collect OSINT data for {target}', 'danger')
        
        return redirect(url_for('osint_dashboard'))
    
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text}: {error}", 'danger')
    
    return redirect(url_for('osint_dashboard'))

@app.route('/osint/<int:osint_id>')
@login_required
def osint_details(osint_id):
    osint_data = OsintData.query.get_or_404(osint_id)
    data = osint_data.get_data()
    
    # Calculate hash for data integrity check
    data_hash = osint_data.data_integrity_check()
    
    return render_template('osint_details.html', 
                          osint_data=osint_data,
                          data=data,
                          data_hash=data_hash)

# Deepfake detection routes
@app.route('/deepfake')
@login_required
def deepfake_dashboard():
    # Get recent deepfake detections
    recent_detections = DeepfakeDetection.query.order_by(DeepfakeDetection.created_at.desc()).limit(10).all()
    
    return render_template('deepfake.html', 
                          recent_detections=recent_detections, 
                          form=DeepfakeForm())

@app.route('/deepfake/detect', methods=['POST'])
@login_required
def detect_deepfake_media():
    form = DeepfakeForm()
    if form.validate_on_submit():
        file_content = form.file_content.data
        filename = secure_filename(form.filename.data)
        media_type = form.media_type.data
        
        # Hash the file content for integrity and deduplication
        file_hash = hashlib.sha256(file_content.encode()).hexdigest()
        
        # Check if this file has been analyzed before
        existing_file = DeepfakeDetection.query.filter_by(file_hash=file_hash).first()
        if existing_file:
            flash(f"This file has already been analyzed. Result: {'Deepfake' if existing_file.is_deepfake else 'Authentic'}", 'info')
            return redirect(url_for('deepfake_dashboard'))
        
        # Analyze the file
        is_deepfake, confidence, features = detect_deepfake(file_content, media_type)
        
        # Save the result
        deepfake_detection = DeepfakeDetection(
            file_hash=file_hash,
            filename=filename,
            media_type=media_type,
            is_deepfake=is_deepfake,
            confidence=confidence
        )
        deepfake_detection.set_features(features)
        db.session.add(deepfake_detection)
        
        # Create an alert if it's a deepfake
        if is_deepfake:
            alert = Alert(
                title=f"Deepfake media detected",
                description=f"File: {filename} - Confidence: {confidence:.2f}",
                severity="high" if confidence > 0.8 else "medium",
                source="deepfake_detection",
                user_id=current_user.id
            )
            db.session.add(alert)
        
        db.session.commit()
        
        result = "Deepfake" if is_deepfake else "Authentic"
        flash(f'Deepfake analysis complete. Result: {result} (Confidence: {confidence:.2f})', 'success')
        return redirect(url_for('deepfake_dashboard'))
    
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text}: {error}", 'danger')
    
    return redirect(url_for('deepfake_dashboard'))

# Alerts route
@app.route('/alerts')
@login_required
def view_alerts():
    alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.timestamp.desc()).all()
    return render_template('alerts.html', alerts=alerts)

@app.route('/alerts/mark_read/<int:alert_id>', methods=['POST'])
@login_required
def mark_alert_read(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    
    # Check if user owns this alert
    if alert.user_id != current_user.id:
        flash('You do not have permission to modify this alert', 'danger')
        return redirect(url_for('view_alerts'))
    
    alert.is_read = True
    db.session.commit()
    
    return redirect(url_for('view_alerts'))

# Threat Analysis route
@app.route('/threat_analysis')
@login_required
def threat_analysis():
    # Generate a comprehensive threat report
    honeypots = Honeypot.query.filter_by(user_id=current_user.id).all()
    honeypot_ids = [h.id for h in honeypots]
    
    attacks = []
    if honeypot_ids:
        attacks = HoneypotAttack.query.filter(HoneypotAttack.honeypot_id.in_(honeypot_ids)).all()
    
    phishing_urls = PhishingUrl.query.filter_by(is_phishing=True).all()
    deepfakes = DeepfakeDetection.query.filter_by(is_deepfake=True).all()
    
    report = generate_threat_report(attacks, phishing_urls, deepfakes)
    
    return render_template('threat_analysis.html', report=report)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
