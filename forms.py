from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, URL, NumberRange, Optional

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class HoneypotForm(FlaskForm):
    name = StringField('Honeypot Name', validators=[DataRequired(), Length(max=64)])
    description = TextAreaField('Description', validators=[Length(max=256)])
    ip_address = StringField('IP Address', validators=[DataRequired()])
    port = IntegerField('Port', validators=[DataRequired(), NumberRange(min=1, max=65535)])
    service_type = SelectField('Service Type', choices=[
        ('http', 'HTTP'),
        ('ssh', 'SSH'),
        ('ftp', 'FTP'),
        ('smtp', 'SMTP'),
        ('telnet', 'Telnet')
    ], validators=[DataRequired()])
    submit = SubmitField('Create Honeypot')

class PhishingUrlForm(FlaskForm):
    url = StringField('URL to Analyze', validators=[DataRequired(), URL()])
    submit = SubmitField('Analyze URL')

class OsintForm(FlaskForm):
    target = StringField('Target (Domain/IP/Email)', validators=[DataRequired()])
    data_type = SelectField('Data Type', choices=[
        ('whois', 'WHOIS Information'),
        ('dns', 'DNS Records'),
        ('geo', 'Geolocation'),
        ('email', 'Email Information'),
        ('headers', 'HTTP Headers'),
        ('ssl', 'SSL Certificate')
    ], validators=[DataRequired()])
    submit = SubmitField('Gather Data')

class DeepfakeForm(FlaskForm):
    file_content = TextAreaField('File Content (Base64)', validators=[DataRequired()])
    filename = StringField('Filename', validators=[DataRequired()])
    media_type = SelectField('Media Type', choices=[
        ('image', 'Image'),
        ('video', 'Video'),
        ('audio', 'Audio')
    ], validators=[DataRequired()])
    submit = SubmitField('Detect Deepfake')
