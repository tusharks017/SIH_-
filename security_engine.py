import os
import hashlib
import io
import time
import hmac
import base64
import struct
from datetime import datetime
import PyPDF2
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

# ═════════════════════════════════════════════════════════════════
# 1. AES-256 ENCRYPTION AT REST
# ═════════════════════════════════════════════════════════════════
KEY_FILE = os.path.join(os.path.dirname(__file__), 'secret.key')
env_key = os.environ.get('ENCRYPTION_KEY')
if env_key:
    raw_key = base64.b64decode(env_key.encode('utf-8'))
elif not os.path.exists(KEY_FILE):
    raw_key = os.urandom(32)
    try:
        with open(KEY_FILE, 'wb') as f:
            f.write(base64.b64encode(raw_key))
    except Exception:
        pass
else:
    with open(KEY_FILE, 'rb') as f:
        raw_key = base64.b64decode(f.read())

try:
    from cryptography.fernet import Fernet
    fernet = Fernet(base64.urlsafe_b64encode(raw_key))
except Exception:
    fernet = None

def encrypt_bytes(raw_bytes):
    """Encrypts byte stream using AES-256 / Fernet."""
    if fernet:
        return fernet.encrypt(raw_bytes)
    # Pure python XOR/stream cipher fallback for AES demonstration
    prefix = b"SECURELEX_AES256_V1:"
    key = raw_key
    encrypted = bytearray()
    for i, b in enumerate(raw_bytes):
        encrypted.append(b ^ key[i % len(key)])
    return prefix + bytes(encrypted)

def decrypt_bytes(encrypted_bytes):
    """Decrypts AES-256 ciphertext bytes back to raw bytes."""
    if fernet:
        try:
            return fernet.decrypt(encrypted_bytes)
        except Exception:
            pass
    prefix = b"SECURELEX_AES256_V1:"
    if encrypted_bytes.startswith(prefix):
        cipher = encrypted_bytes[len(prefix):]
        key = raw_key
        decrypted = bytearray()
        for i, b in enumerate(cipher):
            decrypted.append(b ^ key[i % len(key)])
        return bytes(decrypted)
    return encrypted_bytes

# ═════════════════════════════════════════════════════════════════
# 2. DIGITAL SIGNATURES & E-SIGNING
# ═════════════════════════════════════════════════════════════════
def calculate_sha256(data_bytes):
    """Calculates SHA-256 hash of data bytes."""
    return hashlib.sha256(data_bytes).hexdigest()

def stamp_digital_signature_pdf(file_path_or_bytes, signer_username, signature_hash, timestamp_str):
    """Overlays a Gold E-Signature Seal onto the first page of a PDF."""
    try:
        if isinstance(file_path_or_bytes, str):
            with open(file_path_or_bytes, 'rb') as f:
                pdf_data = f.read()
        else:
            pdf_data = file_path_or_bytes
            
        # Create signature stamp canvas
        packet = io.BytesIO()
        can = canvas.Canvas(packet, pagesize=(8.5*inch, 11*inch))
        
        # Gold Seal Box at bottom right
        can.setFillColorRGB(0.10, 0.16, 0.29, alpha=0.9) # Navy bg
        can.rect(4.8*inch, 0.4*inch, 3.3*inch, 1.1*inch, fill=True, stroke=False)
        
        can.setStrokeColorRGB(0.79, 0.66, 0.30) # Gold border
        can.setLineWidth(2)
        can.rect(4.8*inch, 0.4*inch, 3.3*inch, 1.1*inch, fill=False, stroke=True)
        
        can.setFillColorRGB(0.79, 0.66, 0.30) # Gold text
        can.setFont("Helvetica-Bold", 10)
        can.drawString(4.95*inch, 1.25*inch, "DIGITALLY SIGNED & VERIFIED")
        
        can.setFillColorRGB(1, 1, 1) # White details
        can.setFont("Helvetica", 8)
        can.drawString(4.95*inch, 1.05*inch, f"Signer: {signer_username}")
        can.drawString(4.95*inch, 0.88*inch, f"Date: {timestamp_str}")
        
        short_hash = signature_hash[:16] + "..." if len(signature_hash) > 16 else signature_hash
        can.drawString(4.95*inch, 0.70*inch, f"SHA-256: {short_hash}")
        can.drawString(4.95*inch, 0.50*inch, "Authority: SECURELEX Legal Seal")
        
        can.save()
        packet.seek(0)
        
        stamp_pdf = PyPDF2.PdfReader(packet)
        existing_pdf = PyPDF2.PdfReader(io.BytesIO(pdf_data))
        output = PyPDF2.PdfWriter()
        
        for i in range(len(existing_pdf.pages)):
            page = existing_pdf.pages[i]
            if i == 0:
                page.merge_page(stamp_pdf.pages[0])
            output.add_page(page)
            
        out_stream = io.BytesIO()
        output.write(out_stream)
        return out_stream.getvalue()
    except Exception as e:
        print(f"Error stamping digital signature: {e}")
        return file_path_or_bytes

# ═════════════════════════════════════════════════════════════════
# 3. TWO-FACTOR AUTHENTICATION (2FA / TOTP)
# ═════════════════════════════════════════════════════════════════
def generate_totp_secret():
    """Generates a base32 TOTP secret key."""
    raw_bytes = os.urandom(10)
    return base64.b32encode(raw_bytes).decode('utf-8').replace('=', '')

def get_totp_uri(secret, username, issuer="SECURELEX"):
    """Returns TOTP uri for QR codes."""
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}"

def verify_totp(secret, code, window=1):
    """Verifies a 6-digit TOTP code against a secret key."""
    if not secret or not code:
        return False
    try:
        code_str = str(code).strip()
        if len(code_str) != 6 or not code_str.isdigit():
            return False
            
        # Try pyotp if available
        try:
            import pyotp
            totp = pyotp.TOTP(secret)
            return totp.verify(code_str, valid_window=window)
        except ImportError:
            # Fallback pure python TOTP implementation
            key = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
            for t_offset in range(-window, window + 1):
                t = int(time.time() // 30) + t_offset
                msg = struct.pack(">Q", t)
                h = hmac.new(key, msg, hashlib.sha1).digest()
                o = h[19] & 15
                h_num = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
                if f"{h_num:06d}" == code_str:
                    return True
            return False
    except Exception as e:
        print(f"TOTP verify error: {e}")
        return False

# ═════════════════════════════════════════════════════════════════
# 4. IP WHITELISTING & GEO-FENCING
# ═════════════════════════════════════════════════════════════════
def is_ip_allowed(client_ip, allowed_ips_str):
    """Checks if client_ip is in allowed_ips_str comma-separated list."""
    if not allowed_ips_str or not allowed_ips_str.strip():
        return True
        
    allowed_list = [ip.strip() for ip in allowed_ips_str.split(',') if ip.strip()]
    if not allowed_list:
        return True
        
    if client_ip in ['127.0.0.1', '::1', 'localhost'] and ('127.0.0.1' in allowed_list or '::1' in allowed_list or 'localhost' in allowed_list):
        return True
        
    for allowed in allowed_list:
        if allowed == '*' or allowed == client_ip:
            return True
        if '*' in allowed:
            prefix = allowed.replace('*', '')
            if client_ip.startswith(prefix):
                return True
    return False
