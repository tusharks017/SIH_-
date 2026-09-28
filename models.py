from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='viewer') # 'admin' or 'viewer'
    
    # 2FA fields
    totp_secret = db.Column(db.String(100), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    saved_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_data = db.Column(db.LargeBinary, nullable=True)
    case_tag = db.Column(db.String(100), nullable=True)
    category_tag = db.Column(db.String(100), nullable=True)
    access_level = db.Column(db.String(50), nullable=False, default='viewer') # 'admin-only' or 'viewer'
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # AI & Intelligence fields
    expiry_date = db.Column(db.DateTime, nullable=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    parent_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=True)
    extracted_text = db.Column(db.Text, nullable=True)
    ai_summary = db.Column(db.Text, nullable=True)
    
    # Soft delete fields
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    
    # Digital Signature fields
    is_signed = db.Column(db.Boolean, default=False, nullable=False)
    signed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    signed_at = db.Column(db.DateTime, nullable=True)
    signature_hash = db.Column(db.String(100), nullable=True)
    
    uploader = db.relationship('User', foreign_keys=[uploader_id], backref=db.backref('documents', lazy=True))
    signer = db.relationship('User', foreign_keys=[signed_by_id], backref=db.backref('signed_documents', lazy=True))
    versions = db.relationship('Document', backref=db.backref('parent', remote_side=[id]))

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    tag_type = db.Column(db.String(50), nullable=False, default='category') # 'case' or 'category'
    color = db.Column(db.String(30), default='#0f4c81')
    description = db.Column(db.String(255), nullable=True)

class SecuritySetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_whitelist_enabled = db.Column(db.Boolean, default=False, nullable=False)
    allowed_ips = db.Column(db.Text, default='127.0.0.1, ::1')

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    document_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.String(255), nullable=True)
    
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))
    document = db.relationship('Document', backref=db.backref('audit_logs', lazy=True))
