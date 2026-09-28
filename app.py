import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Document, AuditLog, Tag, SecuritySetting
from flask import session, send_file, jsonify
from translations import TRANSLATIONS
import io
import PyPDF2
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from ai_engine import extract_text_from_file, generate_ai_summary, classify_and_tag, detect_pii, redact_document_text
from security_engine import (
    encrypt_bytes, decrypt_bytes, calculate_sha256, stamp_digital_signature_pdf,
    generate_totp_secret, get_totp_uri, verify_totp, is_ip_allowed
)

def log_audit(action, user_id, document_id=None, details=None):
    log = AuditLog(action=action, user_id=user_id, document_id=document_id, details=details)
    db.session.add(log)
    db.session.commit()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'securelex-super-secret-key-prod-2026')

# Database URI (Use Vercel Postgres/Supabase URL or fallback to SQLite in /tmp for serverless)
db_uri = os.environ.get('DATABASE_URL') or os.environ.get('SQLALCHEMY_DATABASE_URI')
if db_uri and db_uri.startswith("postgres://"):
    db_uri = db_uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri or 'sqlite:///' + os.path.join(app.root_path, 'instance', 'sdms.db')

# Upload folder (Use /tmp/uploads on Vercel serverless or local folder)
upload_dir = os.environ.get('UPLOAD_FOLDER') or (
    '/tmp/uploads' if os.environ.get('VERCEL') else os.path.join(app.root_path, 'uploads')
)
app.config['UPLOAD_FOLDER'] = upload_dir
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@app.before_request
def check_ip_whitelist():
    if request.path.startswith('/static') or request.path == '/logout':
        return
    try:
        setting = SecuritySetting.query.first()
        if setting and setting.ip_whitelist_enabled:
            client_ip = request.remote_addr or '127.0.0.1'
            if not is_ip_allowed(client_ip, setting.allowed_ips):
                return "<h1 style='color:#9b2226;text-align:center;margin-top:100px;'>403 SECURITY ACCESS BLOCKED</h1><p style='text-align:center;'>Your IP address (" + client_ip + ") is not whitelisted to access SECURELEX.</p>", 403
    except Exception:
        pass

@app.route('/set_lang/<lang>')
def set_lang(lang):
    if lang in TRANSLATIONS:
        session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

@app.context_processor
def inject_globals():
    lang = session.get('lang', 'en')
    def _(text):
        return TRANSLATIONS.get(lang, {}).get(text, text)
    return dict(_=_, current_lang=lang, current_year=datetime.utcnow().year)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from datetime import datetime, timezone

def timeago(date):
    now = datetime.utcnow()
    diff = now - date
    seconds = diff.total_seconds()
    if seconds < 60:
        return 'just now'
    elif seconds < 3600:
        return f'{int(seconds // 60)} minutes ago'
    elif seconds < 86400:
        return f'{int(seconds // 3600)} hours ago'
    else:
        return f'{int(seconds // 86400)} days ago'

app.jinja_env.filters['timeago'] = timeago

@app.route('/')
@login_required
def index():
    query = request.args.get('q', '')
    sort_by = request.args.get('sort', 'newest')
    
    # Base query: only latest versions (parent_id is null)
    # and not expired (expiry_date is null or > now)
    now = datetime.utcnow()
    docs_query = Document.query.filter(Document.parent_id == None, Document.is_deleted == False)
    docs_query = docs_query.filter((Document.expiry_date == None) | (Document.expiry_date > now))
    
    if current_user.role != 'admin':
        docs_query = docs_query.filter_by(access_level='viewer')
    
    if query:
        docs_query = docs_query.filter(
            (Document.case_tag.contains(query)) |
            (Document.category_tag.contains(query)) |
            (Document.original_filename.contains(query)) |
            (Document.extracted_text.contains(query))
        )
        
    if sort_by == 'oldest':
        docs_query = docs_query.order_by(Document.upload_date.asc())
    elif sort_by == 'name':
        docs_query = docs_query.order_by(Document.original_filename.asc())
    else: # newest
        docs_query = docs_query.order_by(Document.upload_date.desc())
        
    documents = docs_query.all()
    
    admin_stats = {}
    if current_user.role == 'admin':
        admin_stats['total_docs'] = Document.query.filter_by(is_deleted=False).count()
        admin_stats['admin_only_docs'] = Document.query.filter_by(access_level='admin-only', is_deleted=False).count()
        admin_stats['viewer_docs'] = Document.query.filter_by(access_level='viewer', is_deleted=False).count()
        admin_stats['trash_docs'] = Document.query.filter_by(is_deleted=True).count()
        
    return render_template('index.html', documents=documents, query=query, sort_by=sort_by, stats=admin_stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.is_2fa_enabled and user.totp_secret:
                session['pending_2fa_user_id'] = user.id
                return redirect(url_for('verify_2fa_login'))
            login_user(user)
            log_audit('LOGIN', user.id, None, "User logged in successfully")
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'viewer')
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
            
        new_user = User(username=username, password=generate_password_hash(password, method='scrypt'), role=role)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    parent_id = request.args.get('parent_id', type=int)
    parent_doc = None
    if parent_id:
        parent_doc = Document.query.get_or_404(parent_id)
        
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
            
        if file:
            original_filename = secure_filename(file.filename)
            unique_id = str(uuid.uuid4())
            ext = os.path.splitext(original_filename)[1]
            saved_filename = f"{unique_id}{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
            
            raw_bytes = file.read()
            
            # Temporary file write for text extraction
            temp_path = file_path + ".tmp"
            with open(temp_path, 'wb') as f:
                f.write(raw_bytes)
            extracted_text = extract_text_from_file(temp_path)
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
            ai_summary = generate_ai_summary(extracted_text, original_filename) if extracted_text else None
            auto_category, auto_case = classify_and_tag(extracted_text, original_filename)
            
            case_tag = request.form.get('case_tag') or (parent_doc.case_tag if parent_doc else auto_case)
            category_tag = request.form.get('category_tag') or (parent_doc.category_tag if parent_doc else auto_category)
            access_level = request.form.get('access_level', 'viewer')
            
            expiry_str = request.form.get('expiry_date')
            expiry_date = datetime.strptime(expiry_str, '%Y-%m-%d') if expiry_str else None
            
            new_version = 1
            if parent_doc:
                new_version = parent_doc.version + 1
            
            # Encrypt file at rest using AES-256
            encrypted_data = encrypt_bytes(raw_bytes)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            new_doc = Document(
                original_filename=original_filename,
                saved_filename=saved_filename,
                case_tag=case_tag,
                category_tag=category_tag,
                access_level=access_level,
                uploader_id=current_user.id,
                expiry_date=expiry_date,
                version=new_version,
                extracted_text=extracted_text,
                ai_summary=ai_summary
            )
            db.session.add(new_doc)
            db.session.commit() # To get new_doc.id
            
            if parent_doc:
                old_versions = Document.query.filter_by(parent_id=parent_doc.id).all()
                for old in old_versions:
                    old.parent_id = new_doc.id
                parent_doc.parent_id = new_doc.id
                db.session.commit()
                log_audit('UPLOAD_VERSION', current_user.id, new_doc.id, f"Uploaded version {new_version} (AES-256 Encrypted)")
            else:
                log_audit('UPLOAD', current_user.id, new_doc.id, "Uploaded new document (AES-256 Encrypted)")
            
            flash('Document uploaded and AES-256 encrypted successfully!', 'success')
            return redirect(url_for('index'))
            
    return render_template('upload.html', parent_doc=parent_doc)

@app.route('/download/<int:doc_id>')
@login_required
def download(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if current_user.role != 'admin' and doc.access_level == 'admin-only':
        flash('You do not have permission to view this document', 'danger')
        return redirect(url_for('index'))
        
    preview = request.args.get('preview') == '1'
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.saved_filename)
    
    log_audit('PREVIEW' if preview else 'DOWNLOAD', current_user.id, doc.id, f"{'Previewed' if preview else 'Downloaded'} document")
    
    # Read encrypted file and decrypt in-memory
    if not os.path.exists(file_path):
        flash('File storage error: File not found on disk.', 'danger')
        return redirect(url_for('index'))
        
    with open(file_path, 'rb') as f:
        encrypted_bytes = f.read()
    raw_bytes = decrypt_bytes(encrypted_bytes)
    
    # Dynamic Watermarking & Digital Signature Stamping for PDFs
    if doc.original_filename.lower().endswith('.pdf'):
        try:
            # Stamp E-Signature Seal if signed
            if doc.is_signed:
                stamp_time = doc.signed_at.strftime('%Y-%m-%d %H:%M:%S') if doc.signed_at else ''
                signer_name = doc.signer.username if doc.signer else 'Authorized Officer'
                raw_bytes = stamp_digital_signature_pdf(raw_bytes, signer_name, doc.signature_hash or '', stamp_time)
                
            # Dynamic Watermarking
            packet = io.BytesIO()
            can = canvas.Canvas(packet, pagesize=(8.5*inch, 11*inch))
            can.setFont("Helvetica", 40)
            can.setFillColorRGB(0.8, 0.8, 0.8, alpha=0.3)
            can.rotate(45)
            watermark_text = f"CONFIDENTIAL - {current_user.username} - {datetime.utcnow().strftime('%Y-%m-%d')}"
            can.drawString(3*inch, 0, watermark_text)
            can.save()
            packet.seek(0)
            
            new_pdf = PyPDF2.PdfReader(packet)
            existing_pdf = PyPDF2.PdfReader(io.BytesIO(raw_bytes))
            output = PyPDF2.PdfWriter()
            
            for i in range(len(existing_pdf.pages)):
                page = existing_pdf.pages[i]
                page.merge_page(new_pdf.pages[0])
                output.add_page(page)
                
            output_stream = io.BytesIO()
            output.write(output_stream)
            output_stream.seek(0)
            
            return send_file(output_stream, download_name=doc.original_filename, as_attachment=not preview, mimetype='application/pdf')
        except Exception as e:
            print("Watermarking/Signature failed:", e)
            
    return send_file(io.BytesIO(raw_bytes), download_name=doc.original_filename, as_attachment=not preview)

@app.route('/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete(doc_id):
    if current_user.role != 'admin':
        flash('Only admins can delete documents', 'danger')
        return redirect(url_for('index'))
        
    doc = Document.query.get_or_404(doc_id)
    doc.is_deleted = True
    doc.deleted_at = datetime.utcnow()
    
    log_audit('SOFT_DELETE', current_user.id, doc.id, f"Moved document to Recycle Bin: {doc.original_filename}")
    db.session.commit()
    flash('Document moved to Recycle Bin!', 'warning')
    return redirect(url_for('index'))

@app.route('/trash')
@login_required
def trash():
    if current_user.role == 'admin':
        docs = Document.query.filter_by(is_deleted=True).order_by(Document.deleted_at.desc()).all()
    else:
        docs = Document.query.filter_by(is_deleted=True, uploader_id=current_user.id).order_by(Document.deleted_at.desc()).all()
    return render_template('trash.html', documents=docs)

@app.route('/restore/<int:doc_id>', methods=['POST'])
@login_required
def restore(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if current_user.role != 'admin' and doc.uploader_id != current_user.id:
        flash('You do not have permission to restore this document', 'danger')
        return redirect(url_for('trash'))
        
    doc.is_deleted = False
    doc.deleted_at = None
    log_audit('RESTORE', current_user.id, doc.id, f"Restored document from Recycle Bin: {doc.original_filename}")
    db.session.commit()
    flash('Document restored successfully!', 'success')
    return redirect(url_for('trash'))

@app.route('/perm_delete/<int:doc_id>', methods=['POST'])
@login_required
def perm_delete(doc_id):
    if current_user.role != 'admin':
        flash('Only admins can permanently delete documents', 'danger')
        return redirect(url_for('trash'))
        
    doc = Document.query.get_or_404(doc_id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.saved_filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        
    log_audit('PERMANENT_DELETE', current_user.id, None, f"Permanently deleted document: {doc.original_filename}")
    db.session.delete(doc)
    db.session.commit()
    flash('Document permanently deleted from server!', 'success')
    return redirect(url_for('trash'))

@app.route('/tags', methods=['GET', 'POST'])
@login_required
def tags():
    if current_user.role != 'admin':
        flash('Only admins can manage custom tags', 'danger')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        tag_type = request.form.get('tag_type', 'category')
        color = request.form.get('color', '#0f4c81')
        description = request.form.get('description', '').strip()
        
        if not name:
            flash('Tag name is required', 'danger')
        else:
            existing = Tag.query.filter_by(name=name).first()
            if existing:
                flash('A tag with this name already exists', 'danger')
            else:
                new_tag = Tag(name=name, tag_type=tag_type, color=color, description=description)
                db.session.add(new_tag)
                db.session.commit()
                log_audit('CREATE_TAG', current_user.id, None, f"Created custom tag: {name}")
                flash(f'Tag "{name}" created successfully!', 'success')
                return redirect(url_for('tags'))
                
    tags_list = Tag.query.order_by(Tag.tag_type, Tag.name).all()
    return render_template('tags.html', tags=tags_list)

@app.route('/tags/delete/<int:tag_id>', methods=['POST'])
@login_required
def delete_tag(tag_id):
    if current_user.role != 'admin':
        flash('Only admins can delete tags', 'danger')
        return redirect(url_for('tags'))
        
    tag_obj = Tag.query.get_or_404(tag_id)
    tag_name = tag_obj.name
    db.session.delete(tag_obj)
    db.session.commit()
    log_audit('DELETE_TAG', current_user.id, None, f"Deleted tag: {tag_name}")
    flash(f'Tag "{tag_name}" deleted.', 'info')
    return redirect(url_for('tags'))

@app.route('/history/<int:doc_id>')
@login_required
def history(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if current_user.role != 'admin' and doc.access_level == 'admin-only':
        flash('You do not have permission', 'danger')
        return redirect(url_for('index'))
    versions = Document.query.filter_by(parent_id=doc.id).order_by(Document.version.desc()).all()
    return render_template('history.html', doc=doc, versions=versions)

@app.route('/summarize/<int:doc_id>')
@login_required
def summarize(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if current_user.role != 'admin' and doc.access_level == 'admin-only':
        flash('You do not have permission', 'danger')
        return redirect(url_for('index'))
        
    if not doc.ai_summary and doc.extracted_text:
        doc.ai_summary = generate_ai_summary(doc.extracted_text, doc.original_filename)
        db.session.commit()
        
    return jsonify({
        'status': 'success',
        'doc_id': doc.id,
        'filename': doc.original_filename,
        'summary': doc.ai_summary or "No summary available for this document."
    })

@app.route('/redact/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def redact(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if current_user.role != 'admin' and doc.access_level == 'admin-only':
        flash('You do not have permission', 'danger')
        return redirect(url_for('index'))
        
    detected_pii = detect_pii(doc.extracted_text or "")
    
    if request.method == 'POST':
        terms = request.form.get('terms', '').split('\n')
        auto_pii = request.form.get('auto_pii') == '1'
        
        redacted_text = redact_document_text(doc.extracted_text or "", terms, auto_pii=auto_pii)
        
        # Save as a new redacted text file / document
        unique_id = str(uuid.uuid4())
        saved_filename = f"{unique_id}_REDACTED.txt"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"=== SECURELEX AI REDACTED COPY ===\nOriginal Document: {doc.original_filename}\nRedacted By: {current_user.username}\n\n{redacted_text}")
            
        redacted_filename = f"REDACTED_{doc.original_filename}.txt"
        new_doc = Document(
            original_filename=redacted_filename,
            saved_filename=saved_filename,
            case_tag=doc.case_tag,
            category_tag=f"{doc.category_tag or 'Document'} (Redacted)",
            access_level=doc.access_level,
            uploader_id=current_user.id,
            extracted_text=redacted_text,
            ai_summary=f"Redacted copy of {doc.original_filename}."
        )
        db.session.add(new_doc)
        db.session.commit()
        
        log_audit('REDACT', current_user.id, new_doc.id, f"Created redacted copy of {doc.original_filename}")
        flash('Redacted document created successfully!', 'success')
        return redirect(url_for('index'))
        
@app.route('/sign/<int:doc_id>', methods=['POST'])
@login_required
def sign(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if current_user.role != 'admin' and doc.access_level == 'admin-only':
        flash('You do not have permission to sign this document', 'danger')
        return redirect(url_for('index'))
        
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.saved_filename)
    if not os.path.exists(file_path):
        flash('Document file missing', 'danger')
        return redirect(url_for('index'))
        
    with open(file_path, 'rb') as f:
        encrypted_bytes = f.read()
    raw_bytes = decrypt_bytes(encrypted_bytes)
    
    sha256_hash = calculate_sha256(raw_bytes)
    now = datetime.utcnow()
    
    doc.is_signed = True
    doc.signed_by_id = current_user.id
    doc.signed_at = now
    doc.signature_hash = sha256_hash
    db.session.commit()
    
    log_audit('DIGITAL_SIGN', current_user.id, doc.id, f"Digitally signed document (SHA-256: {sha256_hash[:16]}...)")
    flash('Document digitally signed with SHA-256 seal!', 'success')
    return redirect(url_for('index'))

@app.route('/login/2fa', methods=['GET', 'POST'])
def verify_2fa_login():
    user_id = session.get('pending_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))
        
    user = User.query.get(user_id)
    if not user:
        session.pop('pending_2fa_user_id', None)
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        if verify_totp(user.totp_secret, otp_code):
            session.pop('pending_2fa_user_id', None)
            login_user(user)
            log_audit('LOGIN_2FA', user.id, None, "Verified 2FA & logged in successfully")
            flash('2FA verification successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid 2FA verification code. Try again.', 'danger')
            
    return render_template('2fa.html', user=user)

@app.route('/settings/2fa')
@login_required
def settings_2fa():
    secret = current_user.totp_secret or generate_totp_secret()
    uri = get_totp_uri(secret, current_user.username)
    return render_template('settings_2fa.html', secret=secret, uri=uri)

@app.route('/enable_2fa', methods=['POST'])
@login_required
def enable_2fa():
    secret = request.form.get('secret', '').strip()
    otp_code = request.form.get('otp_code', '').strip()
    
    if verify_totp(secret, otp_code):
        current_user.totp_secret = secret
        current_user.is_2fa_enabled = True
        db.session.commit()
        log_audit('ENABLE_2FA', current_user.id, None, "Enabled Two-Factor Authentication")
        flash('Two-Factor Authentication activated successfully!', 'success')
    else:
        flash('Invalid code. Could not activate 2FA.', 'danger')
        
    return redirect(url_for('settings_2fa'))

@app.route('/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    current_user.is_2fa_enabled = False
    db.session.commit()
    log_audit('DISABLE_2FA', current_user.id, None, "Disabled Two-Factor Authentication")
    flash('Two-Factor Authentication disabled.', 'warning')
    return redirect(url_for('settings_2fa'))

@app.route('/security_settings', methods=['GET', 'POST'])
@login_required
def security_settings():
    if current_user.role != 'admin':
        flash('Only admins can access security settings', 'danger')
        return redirect(url_for('index'))
        
    setting = SecuritySetting.query.first()
    if not setting:
        setting = SecuritySetting(ip_whitelist_enabled=False, allowed_ips='127.0.0.1, ::1')
        db.session.add(setting)
        db.session.commit()
        
    if request.method == 'POST':
        setting.ip_whitelist_enabled = request.form.get('ip_whitelist_enabled') == '1'
        setting.allowed_ips = request.form.get('allowed_ips', '127.0.0.1, ::1').strip()
        db.session.commit()
        log_audit('UPDATE_SECURITY_SETTING', current_user.id, None, f"Updated IP Whitelisting (Enabled: {setting.ip_whitelist_enabled})")
        flash('Security settings updated successfully!', 'success')
        return redirect(url_for('security_settings'))
        
    client_ip = request.remote_addr or '127.0.0.1'
    return render_template('security_settings.html', setting=setting, client_ip=client_ip)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
